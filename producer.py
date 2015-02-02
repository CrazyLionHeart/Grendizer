#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    import json
    import logging
    from stompest.config import StompConfig
    from stompest.sync import Stomp

    from Grendizer.config import config

    from raven import Client

except ImportError, e:
    raise e

activemq = config['activemq']
default_uri = '''failover:(tcp://%(host)s:%(port)d,tcp://%(host)s:%(port)d)?randomize=%(randomize)s,startupMaxReconnectAttempts=%(startupMaxReconnectAttempts)d,initialReconnectDelay=%(initialReconnectDelay)d,maxReconnectDelay=%(maxReconnectDelay)d,maxReconnectAttempts=%(maxReconnectAttempts)d''' % activemq[
    'stomp']
queue = "/topic/%s" % config['queue']['BotNet']

logger = logging.getLogger(__name__)

dsn = 'http://%(public)s:%(private)s@%(host)s' % config['Raven']
client = Client(dsn)


def Producer(account, message):

    def documentCreateNotice():
        result = dict(
            body=dict(
                func_name="documentCreateNotice",
                func_args=[
                    {"doc_type": "importEmail"}]
            ),
            recipient="*",
            profile="user",
            tag="grendizer"
        )
        return json.dumps(result)

    def Send_Notify(message):
        result = dict(
            body=dict(
                func_name="toastr.info",
                func_args=[message]
            ),
            recipient="*",
            profile="user",
            tag="grendizer"
        )
        return json.dumps(result)

    def clearNotice():
        result = dict(
            body=dict(
                func_name="toastr.clear",
                func_args=[]
            ),
            recipient="*",
            profile="user",
            tag="grendizer"
        )
        return json.dumps(result)

    send_notify = Send_Notify(message)
    clear_notice = clearNotice()
    notice = documentCreateNotice()
    logger.debug(u"Отправляем сообщение: %s" % message)
    client = Stomp(StompConfig(default_uri))
    client.connect()
    client.send(queue, notice)
    client.send(queue, send_notify)
    client.send(queue, clear_notice)
    client.disconnect()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    Producer().run()
