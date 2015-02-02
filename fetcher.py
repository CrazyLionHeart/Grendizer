#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    from imapclient import IMAPClient

    from Grendizer.eml_parser import decode_email_s
    from Grendizer.storer import Storage
    from Grendizer.config import statsd

    import logging
    import json

except ImportError as e:
    raise e


def search(id, messages, key):
    with statsd.timer(__name__):
        return [element for element in messages if element[key] == id]


class Fetcher(object):

    INBOX = 'INBOX'
    TRASH = 'INBOX.Trash'

    def __init__(self, options):
        if options:
            self._options = options
        else:
            raise Exception("Cannot create object")

    @property
    def options(self):
        return self._options

    @property
    def log(self):
        return logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def get(self, message_id, include_raw_body=True,
            include_attachment_data=True):

        with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):

            msg = False

            try:
                server = IMAPClient(host=self.options.get('host'),
                                    port=self.options.get('port'),
                                    ssl=self.options.get('ssl'))
                server.debug = self.options.get('debug')

                self.log.debug("Logging to server...")

                server.login(
                    self.options['username'], self.options['password'])

                select_info = server.select_folder(self.INBOX)
                self.log.debug(
                    '%d messages in \"%s\"' % (select_info['EXISTS'],
                                               self.INBOX))

                response = server.fetch(message_id, ['RFC822'])

                # Loop through message ID, parse the messages
                # and extract the required info
                for messagegId, data in response.iteritems():

                    messageString = data['RFC822']

                    msg = decode_email_s(messageString.encode('latin1'),
                                         include_raw_body=include_raw_body,
                                         include_attachment_data=include_attachment_data)
                    msg['id'] = message_id

            except Exception as detail:
                self.log.error(self.options, exc_info=True)
                self.log.exception(detail)

            finally:

                try:
                    server.close_folder()
                    self.log.debug("Exiting from server...")

                    server.logout()
                except:
                    pass

                return msg

    def fetch(self, since=None):
        with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
            result = False
            try:
                server = IMAPClient(host=self.options.get('host'),
                                    port=self.options.get('port'),
                                    ssl=self.options.get('ssl'))
                server.debug = self.options.get('debug')

                self.log.debug("Logging to server...")

                server.login(
                    self.options['username'], self.options['password'])

                select_info = server.select_folder(self.INBOX)
                self.log.debug(
                    '%d messages in \"%s\" on account: %s' %
                    (select_info['EXISTS'], self.INBOX,
                     self.options['username']))

                if not since:
                    b = server.search(['NOT DELETED'])

                    a = Storage(self.options['username']).list(
                        sort={'key': 'id', 'direction': 'desc'},
                        returns=['id'])

                    if a:
                        a = [(k['id']) for k in a]

                        self.log.info("A: %s" % a)
                        self.log.info("B: %s" % b)

                        messages_set = [x for x in b if x not in a]
                    else:
                        messages_set = b

                    self.log.info(messages_set)

                else:
                    messages_set = server.search(
                        ['UID %s:*' % since, 'NOT DELETED'])

                self.log.info("Messages found: %s" % messages_set)

                for message in messages_set:

                    response = server.fetch(message, ['RFC822'])

                    # Loop through message ID, parse the messages
                    # and extract the required info
                    for messagegId, data in response.iteritems():

                        messageString = data['RFC822']
                        try:
                            msg = decode_email_s(
                                messageString.encode('latin1'),
                                include_raw_body=False,
                                include_attachment_data=False)
                            msg['id'] = messagegId
                            msg['_id'] = messagegId
                            msg.pop("rfc822", None)

                            try:
                                msg = json.loads(
                                    json.dumps(msg),
                                    encoding='utf-8')
                            except Exception:
                                pass

                            Storage(self.options['username']).append(msg)

                        except Exception, e:
                            self.log.exception(e)

                result = len(messages_set)

            except (IMAPClient.Error, IMAPClient.AbortError) as detail:
                self.log.error(self.options, exc_info=True)
                self.log.exception(detail)

                try:
                    server.close_folder()
                    self.log.debug("Exiting from server...")

                    server.logout()
                except:
                    pass

                return result
            except Exception as detail:
                self.log.exception(detail)

    def create_folder(self, folder):
        with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
            result = False
            try:
                server = IMAPClient(host=self.options.get('host'),
                                    port=self.options.get('port'),
                                    ssl=self.options.get('ssl'))
                server.debug = self.options.get('debug')

                self.log.debug("Logging to server...")

                server.login(
                    self.options['username'], self.options['password'])

                if not server.folder_exists(folder):
                    result = server.create_folder(folder)
                else:
                    result = server.folder_status(folder)

                return result

            except (IMAPClient.Error, IMAPClient.AbortError) as detail:
                self.log.error(self.options, exc_info=True)
                self.log.exception(detail)

                try:
                    server.close_folder()
                    self.log.debug("Exiting from server...")

                    server.logout()
                except:
                    pass

                return result
            except Exception as detail:
                self.log.exception(detail)

    def remove(self, messages):
        with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
            result = False
            try:
                server = IMAPClient(host=self.options.get('host'),
                                    port=self.options.get('port'),
                                    ssl=self.options.get('ssl'))
                server.debug = self.options.get('debug')

                self.log.debug("Messages: %s" % messages)

                self.log.debug("Logging to server...")

                server.login(
                    self.options['username'], self.options['password'])

                server.select_folder(self.INBOX)

                if not server.folder_exists(self.TRASH):
                    self.create_folder(self.TRASH)

                result_copy = server.copy(messages, self.TRASH)
                result_remove = server.delete_messages(messages)

                self.log.info(result_copy)
                self.log.info(result_remove)

                return result_remove

            except (IMAPClient.Error, IMAPClient.AbortError) as detail:
                self.log.error(self.options, exc_info=True)
                self.log.exception(detail)

                try:
                    server.close_folder()
                    self.log.debug("Exiting from server...")

                    server.logout()
                except:
                    pass

                return result
            except Exception as detail:
                self.log.exception(detail)

    def search(self, key, value):
        with statsd.timer('%s.%s' % (__name__, self.__class__.__name__)):
            result = False
            try:
                server = IMAPClient(host=self.options.get('host'),
                                    port=self.options.get('port'),
                                    ssl=self.options.get('ssl'))
                server.debug = self.options.get('debug')

                self.log.debug("Logging to server...")

                server.login(
                    self.options['username'], self.options['password'])

                select_info = server.select_folder(self.INBOX)
                self.log.debug(
                    '%d messages in \"%s\"' % (select_info['EXISTS'],
                                               self.INBOX))

                messages_set = server.search(['%s %s' % (key, value)])

                if messages_set:
                    result = messages_set[0]

            except (IMAPClient.Error, IMAPClient.AbortError) as detail:
                self.log.error(self.options, exc_info=True)
                self.log.exception(detail)

                try:
                    server.close_folder()
                    self.log.debug("Exiting from server...")

                    server.logout()
                except:
                    pass

                return result
            except Exception as detail:
                self.log.exception(detail)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
