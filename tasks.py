#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    from Grendizer.celery_worker import app
    from Grendizer.fetcher import Fetcher
    from Grendizer.producer import Producer
    from Grendizer.storer import Storage
    from Grendizer.config import config, statsd
    from Grendizer.FileStorage import Storage as FileStorage

    import requests
    import json
    from base64 import b64decode
    import logging
    import redis

    from celery.utils.log import get_task_logger
    from celery import signature, chain, chord, subtask
    from celery.signals import after_task_publish
    from celery.signals import before_task_publish, task_prerun
    from celery.signals import task_postrun, task_retry, task_success
    from celery.signals import task_failure, task_revoked
    from celery.exceptions import Ignore


except ImportError as e:
    raise e


url = 'http://%s/ajax/submitajax.php' % config["obs"]
user = 'system'
password = 'system_1234'
lock_expire = config['celery']['CELERYBEAT_SCHEDULE'][
    'every-30-seconds']['schedule'].total_seconds()

auth = requests.auth.HTTPBasicAuth(user, password)


def search(id, messages, key):
    return [element for element in messages if element[key] == id]


@before_task_publish.connect
def before_task_publish_handler(body, exchange, routing_key, headers,
                                properties, declare, retry_policy, *args,
                                **kwargs):
    logger = get_task_logger(__name__)
    logger.info("before_task_publish")


@after_task_publish.connect
def after_task_publish_handler(body, exchange, routing_key, *args, **kwargs):
    logger = get_task_logger(__name__)
    logger.info("after_task_publish")


@task_prerun.connect
def task_prerun_handler(task_id, task, *arg, **kwargs):
    logger = get_task_logger(__name__)
    logger.info("task_prerun")


@task_postrun.connect
def task_postrun_handler(task_id, task, args, kwargs, retval, state, signal,
                         sender):
    logger = get_task_logger(__name__)
    logger.info("task_postrun")


@task_retry.connect
def task_retry_handler(request, reason, einfo, *args, **kwargs):
    logger = get_task_logger(__name__)
    logger.info("task_retry")


@task_success.connect
def task_success_handler(result, *args, **kwargs):
    logger = get_task_logger(__name__)
    logger.info("task_success")


@task_failure.connect
def task_failure_handler(task_id, exception, args, kwargs, traceback, einfo,
                         signal, sender):
    logger = get_task_logger(__name__)
    logger.info("task_failure")


@task_revoked.connect
def task_revoked_handler(request, terminated, signum, expired, *args,
                         **kwargs):
    logger = get_task_logger(__name__)
    logger.info("task_revoked")


@app.task(max_retries=5, default_retry_delay=3, bind=True)
def push_email(self, *args, **kwargs):

    with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):

        logger = get_task_logger(__name__)
        logger.debug(args)
        logger.debug(kwargs)

        account = kwargs.get('account')
        Id = kwargs.get('Id')

        if (not Id) and (not account):
            account = args[0]['account']
            Id = args[0]['Id']

        have_lock = False
        my_lock = redis.Redis(**config['redis']).lock("grendizer_%s_%s" %
                             (self.__name__, account['username']),
            timeout=lock_expire)
        try:
            have_lock = my_lock.acquire(blocking=False)
            if have_lock:
                logger.info("We have a lock")
                account['debug'] = False
                fetcher = Fetcher(account)
                result = fetcher.fetch(Id)

                logger.debug("Fetch result: %s" % result)
                if result:
                    message = u"Появилось %d новых писем в аккаунте %s" % (
                        result, account['username'])
                    Producer(account['username'], message)
                    return result
            else:
                logger.info("We have not lock @ %s: %s" % (self.__name__,
                            account['username']))
                # raising Ignore here means that it will not update the state
                # of the task (i.e. SUCCESS).
                raise Ignore()

        except Ignore as exc:
            if have_lock:
                my_lock.release()
            raise self.retry(exc=exc)
        except Exception as exc:
            logger.error(exc, exc_info=True)
            if have_lock:
                my_lock.release()
            raise self.retry(exc=exc)
        finally:
            if have_lock:
                my_lock.release()


@app.task(max_retries=5, default_retry_delay=3, bind=True)
def remove_email(self, account, Ids, *args, **kwargs):
    with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
        logger = get_task_logger(__name__)
        logger.debug(args)
        logger.debug(kwargs)

        if not account:
            account = kwargs.get('account')

            if not account:
                return account

        if not Ids:
            Ids = kwargs.get('Ids')

            if not Ids:
                return Ids

        logger.debug(Ids)

        have_lock = False
        my_lock = redis.Redis(**config['redis']).lock("grendizer_%s_%s" %
                             (self.__name__, account['username']),
            timeout=lock_expire)
        try:
            have_lock = my_lock.acquire(blocking=False)
            if have_lock:
                logger.info("We have a lock")

                fetcher = Fetcher(account)
                storage = Storage(account['username'])

                imap_result = fetcher.remove(Ids)
                mongo_result = storage.delete(Ids)

                logger.info(imap_result)
                logger.info(mongo_result)

                if imap_result:
                    imap_result = u"Успех"
                else:
                    imap_result = u"Неудача"

                if mongo_result:
                    mongo_result = u"Успех"
                else:
                    mongo_result = u"Неудача"

                message = u"""1 письмо (%s) было удалено в аккаунте %s
                c почтового сервера со статусом: "%s" и
                 локального хранилища со статусом: "%s" """ % (
                    Ids,
                    account['username'],
                    imap_result,
                    mongo_result)

                Producer(account['username'], message)
            else:
                logger.info("We have not lock @ %s: %s" % (self.__name__,
                            account['username']))
                # raising Ignore here means that it will not update the state
                # of
                # the task (i.e. SUCCESS).
                raise Ignore()

        except Ignore as exc:
            if have_lock:
                my_lock.release()
            raise self.retry(exc=exc)
        except Exception as exc:
            logging.error(exc, exc_info=True)
            if have_lock:
                my_lock.release()
            raise self.retry(exc=exc)
        finally:
            if have_lock:
                my_lock.release()


@app.task(max_retries=5, default_retry_delay=3, bind=True)
def search_email(self, *args, **kwargs):
    with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
        logger = get_task_logger(__name__)
        logger.debug(args)
        logger.debug(kwargs)

        account = kwargs.get('account')

        Id = kwargs.get('Id')

        if not account:
            raise Exception("No Account for search")

        if (not Id) and (not account):
            account = args[0]['account']
            Id = args[0]['Id']

        if not Id:
            raise Exception("No Id for search")

        try:
            account['debug'] = False
            fetcher = Fetcher(account)
            return dict(account=account, Id=fetcher.search("EXISTS", Id))
        except Exception as exc:
            logging.error(exc, exc_info=True)
            raise self.retry(exc=exc)


@app.task(max_retries=5, default_retry_delay=10, bind=True, trail=True)
def make_external_doc(self, *args, **kwargs):
    with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
        logger = get_task_logger(__name__)
        try:
            guid, filename, database, docFile_name, content_type, callback = args[
                0]

            filtersMain = dict(groupOp="AND", rules=[dict(field="doc_pin",
                                                          data=guid, op="eq")]
                               )

            payload = dict(ajtype='jqGrid', datatype='docs_list',
                           filtersMain=json.dumps(filtersMain))

            r = requests.post(url, auth=auth, data=payload)
            r.raise_for_status()
            logger.debug("Service response: %s" % r.text)
            headers = r.json()
            doc_name = headers[0].get('name')

            payload = dict(file_name="%s: %s" % (doc_name, docFile_name),
                           file_hash=filename,
                           db_name=database,
                           content_type=content_type,
                           ajtype='external_doc',
                           datatype='create',
                           doc_props=json.dumps(dict(
                               contragent_pin=headers[0]['contragent_pin'],
                               contragent_name=headers[0]['contragent_name'],
                               agent_pin=headers[0]['agent_pin'],
                               agent_name=headers[0]['agent_name'])
                           ),
                           parent_doc_pin=guid)

            if callback:
                payload['callback'] = callback

            r = requests.post(url, auth=auth, data=payload)
            r.raise_for_status()
            logger.debug("Service response: %s" % r.text)
            return r.json()
        except Exception as exc:
            logging.error(exc, exc_info=True)
            raise self.retry(exc=exc)


@app.task(max_retries=5, default_retry_delay=3, bind=True, trail=True)
def CloseDoc(self, *args, **kwargs):
    with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
        logger = get_task_logger(__name__)
        try:
            logger.info("doc closing")

            _, guid = args

            logger.info("Closing document: %s" % guid)

            payload = dict(
                ajtype='jqGridAllSave', datatype='email_message',
                json_row_data=json.dumps(
                    [{'doc_pin': guid,
                      'price_closed': 't'}]))

            r = requests.post(url, auth=auth, data=payload)
            r.raise_for_status()
            logger.info("Doc closed with response: %s" %
                        r.text)
            return r.json()

        except Exception as exc:
            logging.error(exc, exc_info=True)
            raise self.retry(exc=exc)


@app.task(max_retries=5, default_retry_delay=10, bind=True, trail=True)
def insdel(self, *args, **kwargs):
    with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):

        logger = get_task_logger(__name__)

        try:
            logger.info("doc insdel")

            group_result, guid = args

            to_insert = []

            for element in group_result:

                logger.info(element)

                to_insert.append(
                    {
                        "parent_doc_pin": guid,
                        "doc_pin": element['data']['compose']['target'],
                        "doc_type": "external_doc"
                    }
                )

            if len(to_insert):
                payload = dict(
                    ajtype='insdel',
                    datatype="doc_docs",
                    b_del="N",
                    json_row_data=json.dumps(to_insert)
                )

                r = requests.post(url, auth=auth, data=payload)
                r.raise_for_status()
                logger.info("Doc modified with response: %s" %
                            r.text)
                return r.json()
            else:
                return None

        except Exception as exc:
            logging.exception(exc)
            raise self.retry(exc=exc)


@app.task(max_retries=5, bind=True, trail=True)
def get_list(self, guid, account, message_id, callback):
    with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
        try:
            options = search(account, config['emails'], 'username')[0]
            if not options:
                raise Exception(u"No config for account: %s" % account)

            fetcher = Fetcher(options)

            message = fetcher.get(message_id, False, True)

            external_doc = []

            if message:

                for attachment_key in message['attachments']:
                    current_attachment = message['attachments'][attachment_key]

                    raw = b64decode(current_attachment['raw'])
                    content_type = current_attachment['mime-type']
                    current_attachment.pop("raw", None)
                    metadata = current_attachment

                    database = 'attachments'

                    try:
                        fs = FileStorage.Storage(db=database)

                        res = fs.put(raw, content_type, metadata)
                    except Exception as e:
                        raise e

                    if res:
                            external_doc.append((
                                guid,
                                res['filename'],
                                database,
                                metadata['filename'],
                                content_type,
                                callback)
                            )
            return external_doc
        except Exception as exc:
            logging.exception(exc)
            raise self.retry(exc=exc)


@app.task(bind=True)
def dmap(self, it, callback, chord_callback):
    with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
        # Map a callback over an iterator and return as a group
        callback = subtask(callback)

        if len(it) == 0:
            return chord_callback.delay(it)
        else:
            return chord((callback.clone([arg, ]) for arg in it),
                         chord_callback)()


@app.task(max_retries=5, bind=True, trail=True)
def get_accounts(self):
    with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
        try:
            return [(element, None) for element in config['emails']]
        except Exception as exc:
            logging.exception(exc)
            raise self.retry(exc=exc)


@app.task(max_retries=5, bind=True, trail=True)
def sendNotice(self, *args, **kwargs):
    with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
        try:
            account, result = args[0][0]
            if result:
                message = u"Появилось %d новых писем в аккаунте %s" % (
                    result, account['username'])
                Producer(account['username'], message)
        except Exception as exc:
            logging.exception(exc)
            raise self.retry(exc=exc)


@app.task(max_retries=5, bind=True, default_retry_delay=3, trail=True)
def fetchAll(self, *args, **kwargs):
    with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
        logger = get_task_logger(__name__)
        have_lock = False
        account, Id = args[0]

        my_lock = redis.Redis(**config['redis']).lock("grendizer_%s_%s" %
                             (self.__name__, account['username']),
            timeout=lock_expire)
        try:
            have_lock = my_lock.acquire(blocking=False)
            if have_lock:
                logger.info("We have a lock")

                fetcher = Fetcher(account)
                result = fetcher.fetch(Id)
                return account, result
            else:
                logger.info("We have not lock @ %s: %s" % (self.__name__,
                            account['username']))
                # raising Ignore here means that it will not update the state of
                # the task (i.e. SUCCESS).
                raise Ignore()

        except Ignore as exc:
            if have_lock:
                my_lock.release()
            raise self.retry(exc=exc)
        except Exception as exc:
            logging.error(exc, exc_info=True)
            if have_lock:
                my_lock.release()
            raise self.retry(exc=exc)
        finally:
            if have_lock:
                my_lock.release()


@app.task(max_retries=5, bind=True, trail=True)
def importEmail(self, *args, **kwargs):
    with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
        try:
            get_account_s = signature('Grendizer.tasks.get_accounts')
            fetchAll_s = signature('Grendizer.tasks.fetchAll')
            sendNotice_s = signature('Grendizer.tasks.sendNotice')
            dmap_s = signature(
                'Grendizer.tasks.dmap', args=(fetchAll_s, sendNotice_s))

            return chain(get_account_s, dmap_s)()
        except Exception as exc:
            logging.exception(exc)
            raise self.retry(exc=exc)
