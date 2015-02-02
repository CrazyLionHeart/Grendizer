#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    import sys
    import os

    path = os.path.dirname(sys.modules[__name__].__file__)
    path = os.path.join(path, '..')
    sys.path.insert(0, path)

    from Grendizer.app import app
    import logging

except ImportError as e:
    raise e

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    app.run(debug=True, host='0.0.0.0', port=9393)
