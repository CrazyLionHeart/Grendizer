#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from Grendizer.config import config, statsd

    from pymongo.mongo_replica_set_client import MongoReplicaSetClient
    from pymongo import ASCENDING, DESCENDING
    from pymongo.errors import OperationFailure, ConnectionFailure
    from pymongo.errors import PyMongoError, InvalidStringData
    from pymongo.errors import DuplicateKeyError

    from bson.json_util import dumps

    import json
    import logging

except ImportError as e:
    raise e


class Storage(object):

    def __init__(self, account):
        self.mongodb = config['mongodb']
        self.host = ",".join(self.mongodb['host'])
        self.replicaSet = self.mongodb['replicaSet']
        self.writeConcern = self.mongodb['writeConcern']
        self.journal = self.mongodb['journal']
        self.account = account

    @property
    def log(self):
        return logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def list(self, filters=None, limit=None, sort=None, skip=None,
             returns=None):
        with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):

            try:
                client = MongoReplicaSetClient(self.host,
                                               replicaSet=self.replicaSet,
                                               w=self.writeConcern,
                                               j=self.journal,
                                               slave_okay=True,
                                               connectTimeoutMS=200)

            except ConnectionFailure as e:
                self.log.error("Connection falure error reached: %r" %
                               e, exc_info=True)
                raise Exception(e)

            db = client[self.mongodb['database']]
            collection = db[self.account]

            kwargs = dict()

            if returns:
                kwargs['fields'] = returns

            if skip:
                kwargs['skip'] = skip

            if sort:
                if sort['direction'] == 'asc':
                    sort_direction = ASCENDING
                else:
                    sort_direction = DESCENDING
                # check for index exists
                collection.ensure_index(
                    [(sort['key'], sort_direction)], background=True)

                kwargs['sort'] = [(sort['key'], sort_direction)]

            if limit:
                kwargs['limit'] = limit

            self.log.info(kwargs)
            self.log.info(filters)

            try:
                if filters:
                    results = collection.find(filters, **kwargs)
                else:
                    results = collection.find(**kwargs)

                ret = json.loads(dumps(results))

                client.close()
                return ret
            except PyMongoError as e:
                self.log.error(e, exc_info=True)
                raise Exception(e)

    def count(self, filters):
        with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):

            try:
                client = MongoReplicaSetClient(self.host,
                                               replicaSet=self.replicaSet,
                                               w=self.writeConcern,
                                               j=self.journal,
                                               slave_okay=True,
                                               connectTimeoutMS=200)

            except ConnectionFailure as e:
                self.log.error("Connection falure error reached: %r" %
                               e, exc_info=True)
                raise Exception(e)

            db = client[self.mongodb['database']]
            collection = db[self.account]

            try:
                if filters:
                    results = collection.find(filters).count()
                else:
                    results = db.command('collstats', self.account)['count']
                client.close()
                return results
            except OperationFailure as e:
                self.log.error(e, exc_info=True)
                return 0

    def get(self, message_id):
        with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
            try:
                client = MongoReplicaSetClient(self.host,
                                               replicaSet=self.replicaSet,
                                               w=self.writeConcern,
                                               j=self.journal,
                                               slave_okay=True,
                                               connectTimeoutMS=200)

            except ConnectionFailure as e:
                self.log.error("Connection falure error reached: %r" %
                               e, exc_info=True)
                raise Exception(e)

            db = client[self.mongodb['database']]
            collection = db[self.account]

            try:
                results = collection.find({'id': message_id})

                ret = json.loads(dumps(results))

                client.close()

                return ret
            except PyMongoError as e:
                self.log.error(e, exc_info=True)
                raise Exception(e)

    def append(self, document):
        with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
            try:
                client = MongoReplicaSetClient(self.host,
                                               replicaSet=self.replicaSet,
                                               w=self.writeConcern,
                                               j=self.journal,
                                               slave_okay=True,
                                               connectTimeoutMS=200)

            except ConnectionFailure as e:
                self.log.error("Connection falure error reached: %r" %
                               e, exc_info=True)
                raise Exception(e)

            db = client[self.mongodb['database']]
            collection = db[self.account]

            search = self.list(filters={'id': document['id']})

            if not search:

                try:
                    results = collection.insert(document)

                    ret = json.loads(dumps(results))
                    client.close()
                    return ret
                except PyMongoError as e:
                    self.log.error(e, exc_info=True)
                    raise Exception(e)
                except InvalidStringData as e:
                    self.log.error(e, exc_info=True)
                    raise Exception("Wrong document: %s" % document)
                except DuplicateKeyError:
                    pass

            else:
                return search

    def delete(self, message_id):
        with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
            try:
                client = MongoReplicaSetClient(self.host,
                                               replicaSet=self.replicaSet,
                                               w=self.writeConcern,
                                               j=self.journal,
                                               slave_okay=True,
                                               connectTimeoutMS=200)

            except ConnectionFailure as e:
                self.log.error("Connection falure error reached: %r" %
                               e, exc_info=True)
                raise Exception(e)

            db = client[self.mongodb['database']]
            collection = db[self.account]

            try:
                results = collection.remove({'id': {'$in': message_id}})

                ret = json.loads(dumps(results))
                client.close()

                return ret
            except PyMongoError as e:
                self.log.error(e, exc_info=True)
                raise Exception(e)
