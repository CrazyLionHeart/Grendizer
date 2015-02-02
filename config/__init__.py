#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    from os import environ, path
    import json
    from logging.config import dictConfig
    from datetime import timedelta
    from io import open
    from statsd import StatsClient
except ImportError, e:
    raise e

current_env = environ.get("APPLICATION_ENV", 'development')

try:
    with open(
        '%s/%s/config.%s.json' % (path.dirname(path.abspath(__file__)),
                                  current_env, current_env),
            encoding='utf-8') as f:
        config = json.load(f)
        config["APPLICATION_ENV"] = current_env
        config['celery']['CELERYBEAT_SCHEDULE'][
            'every-30-seconds']['schedule'] = timedelta(seconds=200)
        dictConfig(config["loggingconfig"])

        activemq = config['activemq']
        config['default_uri'] = '''failover:(tcp://%(host)s:%(port)d,tcp://%(host)s:%(port)d)?randomize=%(randomize)s,startupMaxReconnectAttempts=%(startupMaxReconnectAttempts)d,initialReconnectDelay=%(initialReconnectDelay)d,maxReconnectDelay=%(maxReconnectDelay)d,maxReconnectAttempts=%(maxReconnectAttempts)d''' % activemq[
            'stomp']

        statsd = StatsClient(**config['statsd'])


except IOError, e:
    print(
        "Конфиг не найден. Поместите в файл: %s/%s/config.%s.json" % (path.dirname(path.abspath(__file__)),
                                                                      current_env, current_env))
    raise Exception(e)
except ValueError as e:
    raise Exception(e)
