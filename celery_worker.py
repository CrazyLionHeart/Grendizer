#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Grendizer.config import config
from celery import Celery


app = Celery('tasks', include='Grendizer.tasks')
app.conf.update(**config['celery'])


if __name__ == '__main__':
    app.worker_main(
        ['--loglevel=INFO', '-E'])
