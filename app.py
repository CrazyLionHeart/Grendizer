#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    import math
    import json

    from raven.contrib.flask import Sentry
    from raven.middleware import Sentry as SentryMiddleware

    from flask import jsonify, request, url_for

    from Grendizer.JsonApp import make_json_app, crossdomain
    from Grendizer.config import config
    from Grendizer.storer import Storage
    from Grendizer.tasks import push_email, remove_email, make_external_doc
    from Grendizer.tasks import CloseDoc, get_list, dmap, insdel

    from datetime import datetime

    from celery import signature, chain, chord

    import re

except ImportError as e:
    raise e

dsn = "http://%(public)s:%(private)s@%(host)s" % config['Raven']

app = make_json_app(__name__)
app.config['SENTRY_DSN'] = dsn
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
sentry = Sentry(dsn=dsn, logging=True)
sentry.init_app(app)
app.wsgi = SentryMiddleware(app.wsgi_app, sentry.client)


def search(id, messages, key):
    return [element for element in messages if element[key] == id]


@app.route('/')
@crossdomain(origin='*')
def example():
    """Помощь по API"""

    import urllib
    links = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            options = {}
            for arg in rule.arguments:
                options[arg] = "[{0}]".format(arg)

            methods = ','.join(rule.methods)

            url = url_for(rule.endpoint, **options)
            docstring = app.view_functions[rule.endpoint].__doc__
            links.append(
                dict(methods=methods, url=urllib.unquote(url),
                     docstring=docstring))

    return jsonify(results=links)


@app.route('/<account>')
@crossdomain(origin='*')
def list_account(account):

    app.logger.debug("arguments: %s" % request.args)

    page = int(request.args.get('page', 1))
    rows = int(request.args.get('rows', 30))
    sidx = request.args.get("sidx")
    sord = request.args.get("sord")
    _search = request.args.get("_search")
    gridFilters = request.args.get("filters")
    filtersMain = request.args.get("filtersMain")
    showcols = request.args.get("showcols")

    if not gridFilters:
        gridFilters = {"groupOp": "AND", "rules": []}
    else:
        gridFilters = json.loads(gridFilters)

    if not filtersMain:
        filtersMain = {"groupOp": "AND", "rules": []}
    else:
        filtersMain = json.loads(filtersMain)

    if showcols:
        showcols = showcols.split(',')

        showcols = [elem for elem in showcols if elem.upper() != elem]

    filters = {}
    sort = None

    if _search:
        for rule in filtersMain['rules']:

            if not filters.get(rule['field']):

                if rule.get('fieldtype') is not None and \
                    (rule['fieldtype'] == 'datetime' or
                        rule['fieldtype'] == 'date'):
                    filters[rule['field']] = dict()
                else:
                    filters[rule['field']] = list()

            if rule.get('fieldtype') is not None \
                    and rule['fieldtype'] == 'datetime':
                rule['data'] = datetime.strptime(
                    rule['data'], '%d.%m.%Y %H:%M')

            if rule.get('fieldtype') is not None and \
                    rule['fieldtype'] == 'date':
                rule['data'] = datetime.strptime(rule['data'], '%d.%m.%Y')

            if rule['op'] == "bw":
                filters[rule['field']] = {
                    '$regex': re.compile("^%s" % rule['data'], re.UNICODE)}

            elif rule['op'] == "ew":
                filters[rule['field']] = {
                    '$regex': re.compile("%s$" % rule['data'], re.UNICODE)}

            elif rule['op'] == "eq":
                filters[rule['field']].append(rule['data'])

            elif rule['op'] == "ne":
                filters[rule['field']].append({'$ne': rule['data']})

            elif rule['op'] == "lt":
                if rule.get('fieldtype') is not None and \
                    (rule['fieldtype'] == 'datetime' or
                     rule['fieldtype'] == 'date'):
                    rule['data'] = datetime(rule['data'].year, rule[
                                            'data'].month, rule['data'].day,
                                            23, 59, 59, 999999)
                    filters[rule['field']]['$lt'] = rule['data']
                else:
                    filters[rule['field']].append({'$lt': rule['data']})

            elif rule['op'] == "le":
                if rule.get('fieldtype') is not None and \
                    (rule['fieldtype'] == 'datetime' or
                        rule['fieldtype'] == 'date'):
                    rule['data'] = datetime(rule['data'].year, rule[
                                            'data'].month, rule['data'].day,
                                            23, 59, 59, 999999)
                    filters[rule['field']]['$lte'] = rule['data']
                else:
                    filters[rule['field']].append({'$lte': rule['data']})

            elif rule['op'] == "gt":
                if rule.get('fieldtype') is not None and  \
                    (rule['fieldtype'] == 'datetime' or
                        rule['fieldtype'] == 'date'):
                    filters[rule['field']]['$gt'] = rule['data']
                else:
                    filters[rule['field']].append({'$gt': rule['data']})

            elif rule['op'] == "ge":
                if rule.get('fieldtype') is not None and \
                    (rule['fieldtype'] == 'datetime' or
                        rule['fieldtype'] == 'date'):
                    filters[rule['field']]['$gte'] = rule['data']
                else:
                    filters[rule['field']].append({'$gte': rule['data']})

            elif rule['op'] == "cn":
                filters[rule['field']].append(
                    {'$text': {'$search': rule['data']}})

            elif rule['op'] == 'nc':
                    filters[rule['field']] = {
                        '$not': re.compile("%s" % rule['data'], re.UNICODE)}
            elif rule['op'] == 'bn':
                filters[rule['field']] = {
                    '$not': re.compile("^%s" % rule['data'], re.UNICODE)}
            elif rule['op'] == 'en':
                filters[rule['field']] = {
                    '$not': re.compile("%s$" % rule['data'], re.UNICODE)}

        if gridFilters.get('rules'):
            for rule in gridFilters['rules']:

                if not filters.get(rule['field']):
                    if rule.get('fieldtype') is not None and \
                        (rule['fieldtype'] == 'datetime' or
                                              rule['fieldtype'] == 'date'):
                        filters[rule['field']] = dict()
                    else:
                        filters[rule['field']] = list()

                if rule.get('fieldtype') is not None and \
                        rule['fieldtype'] == 'datetime':
                    rule['data'] = datetime.strptime(
                        rule['data'], '%d.%m.%Y %H:%M')

                if rule.get('fieldtype') is not None and \
                        rule['fieldtype'] == 'date':
                    rule['data'] = datetime.strptime(rule['data'], '%d.%m.%Y')

                if rule['op'] == "bw":
                    filters[rule['field']] = {
                        '$regex': re.compile("^%s" % rule['data'], re.UNICODE)}

                elif rule['op'] == "ew":
                    filters[rule['field']] = {
                        '$regex': re.compile("%s$" % rule['data'], re.UNICODE)}

                elif rule['op'] == "eq":
                    filters[rule['field']].append(rule['data'])

                elif rule['op'] == "ne":
                    filters[rule['field']].append({'$ne': rule['data']})

                elif rule['op'] == "lt":
                    if rule.get('fieldtype') is not None and \
                        (rule['fieldtype'] == 'datetime' or
                            rule['fieldtype'] == 'date'):
                        filters[rule['field']]['$lt'] = rule['data']
                    else:
                        filters[rule['field']].append({'$lt': rule['data']})

                elif rule['op'] == "le":
                    if rule.get('fieldtype') is not None and \
                        (rule['fieldtype'] == 'datetime' or
                            rule['fieldtype'] == 'date'):
                        filters[rule['field']]['$lte'] = rule['data']
                    else:
                        filters[rule['field']].append({'$lte': rule['data']})

                elif rule['op'] == "gt":
                    if rule.get('fieldtype') is not None and \
                        (rule['fieldtype'] == 'datetime' or
                            rule['fieldtype'] == 'date'):
                        filters[rule['field']]['$gt'] = rule['data']
                    else:
                        filters[rule['field']].append({'$gt': rule['data']})

                elif rule['op'] == "ge":
                    if rule.get('fieldtype') is not None and \
                        (rule['fieldtype'] == 'datetime' or
                            rule['fieldtype'] == 'date'):
                        filters[rule['field']]['$gte'] = rule['data']
                    else:
                        filters[rule['field']].append({'$gte': rule['data']})

                elif rule['op'] == "cn":
                    filters[rule['field']].append(
                        {'$text': {'$search': rule['data']}})

                elif rule['op'] == 'nc':
                        filters[rule['field']] = {
                            '$not': re.compile("%s" % rule['data'],
                                               re.UNICODE)}
                elif rule['op'] == 'bn':
                    filters[rule['field']] = {
                        '$not': re.compile("^%s" % rule['data'], re.UNICODE)}
                elif rule['op'] == 'en':
                    filters[rule['field']] = {
                        '$not': re.compile("%s$" % rule['data'], re.UNICODE)}
    else:
        filters = None

    app.logger.debug("Filters: %s" % filters)

    if sidx:
        if sord:
            sort = dict(key=sidx, direction=sord)

    skip = int((page - 1) * rows)

    all_data = Storage(account).list(filters, limit=rows, sort=sort,
                                     skip=skip, returns=showcols)
    count_data = Storage(account).count(filters)

    total = int(math.ceil(count_data / float(rows)))

    return jsonify(dict(total=total, page=page, rows=all_data,
                        records=count_data))


@app.route('/<account>/<int:message_id>')
@crossdomain(origin='*')
def email(account, message_id):
    options = search(account, config['emails'], 'username')[0]
    if not options:
        raise Exception(u"No config for account: %s" % account)

    result = Storage(account).get(message_id)

    return jsonify(result=result)


@app.route('/<account>', methods=['DELETE'])
@crossdomain(origin='*')
def delete(account):
    options = search(account, config['emails'], 'username')[0]
    message_id = json.loads(request.form.get("message_id", "[]"))

    message_id = [int(x) for x in message_id]
    app.logger.debug("Message Id: %s" % message_id)

    if not options:
        raise Exception(u"No config for account: %s" % account)

    task = remove_email.delay(options, message_id)
    app.logger.debug("Task Id: %s" % task.id)
    return jsonify(results=dict(task_id=task.id))


@app.route('/<account>', methods=['SYNC'])
@crossdomain(origin='*')
def sync_account(account):
    options = search(account, config['emails'], 'username')[0]
    task = push_email.delay(**dict(account=options, Id=None))
    app.logger.debug("Task Id: %s" % task.id)
    return jsonify(results=dict(task_id=task.id))


@app.route('/<account>/<int:message_id>', methods=['IMPORT'])
@crossdomain(origin='*')
def import_attachments(account, message_id):
    guid = request.form.get("guid", None)
    callback = request.form.get("callback", None)
    results = []

    if not guid:
        raise Exception(u"No parent email message")

    closedoc = signature('Grendizer.tasks.CloseDoc', args=(guid,))
    make_external_doc_s = signature('Grendizer.tasks.make_external_doc')
    insdel_s = signature('Grendizer.tasks.insdel', args=(guid,), link=closedoc)
    get_list_s = signature(
        'Grendizer.tasks.get_list', args=(guid, account, message_id, callback))
    dmap_s = signature(
        'Grendizer.tasks.dmap', args=(make_external_doc_s, insdel_s))

    res = chain(get_list_s, dmap_s)()

    results.append(res.id)

    return jsonify(results=results)
