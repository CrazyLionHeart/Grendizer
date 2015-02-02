#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Georges Toth (c) 2013 <georges@trypill.org>
#
# eml_parser is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# eml_parser is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with eml_parser.  If not, see <http://www.gnu.org/licenses/>.
#
#
# Functionality inspired by:
# https://github.com/CybOXProject/Tools/blob/master/scripts/email_to_cybox/email_to_cybox.py
# https://github.com/iscoming/eml_parser/blob/master/eml_parser.py
#

try:
    import sys
    import email
    import getopt
    import re
    import uuid
    import datetime
    import dateutil.tz
    import dateutil.parser
    import base64
    import hashlib
    import chardet
    import quopri
    from urlparse import urlparse

    import html5lib
    from html5lib import sanitizer, treebuilders, treewalkers, serializer


    from Grendizer.config import config

    import magic

    from raven import Client

    import logging

except ImportError as e:
    raise e

logger = logging.getLogger(__name__)

dsn = 'http://%(public)s:%(private)s@%(host)s' % config['Raven']
client = Client(dsn)


# regex compilation
# W3C HTML5 standard recommended regex for e-mail validation
email_regex = re.compile(
    r'''([a-zA-Z0-9.!#$%&'*+-/=?\^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)''', re.MULTILINE)
# /^[a-zA-Z0-9.!#$%&'*+-/=?\^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/
domain_regex = re.compile(
    r'''(?:(?:from|by)\s+)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)''', re.MULTILINE)
ipv4_regex = re.compile(
    r'''((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))''', re.MULTILINE)

b_d_regex = re.compile(r'(localhost|[a-z0-9.\-]+(?:[.][a-z]{2,4})?)')
f_d_regex = re.compile(
    r'from(?:\s+(localhost|[a-z0-9\-]+|[a-z0-9.\-]+[.][a-z]{2,4}))?\s+(?:\(?(localhost|[a-z0-9.\-]+[.][a-z]{2,4})?\s*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\)?)?')
for_d_regex = re.compile(r'for\s+<?([a-z0-9.\-]+@[a-z0-9.\-]+[.][a-z]{2,4})>?')

# note: depending on the text this regex blocks in an infinite loop !
url_regex = re.compile(
    r'''(?i)\b((?:(hxxps?|https?|ftps?)://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?]))''', re.VERBOSE | re.MULTILINE)

# simple version for searching for URLs
url_regex_simple = re.compile(
    r'''(?i)\b((?:(hxxps?|https?|ftps?)://)[^ ]+)''', re.VERBOSE | re.MULTILINE)
#

global_maula = {
    "attachments": {},
    "body": {'plain': '', 'html': ''},
    "cc": [],
    "date": "",
    "from": "",
    "id": None,
    "message_id": "",
    "raw_body": {'plain': '', 'html': ''},
    "received": [],
    "received_domains": [],
    "received_emails": [],
    "received_raw": [],
    "subject": "",
    "to": [],
    "urls": [],
    "x-originating-ip": "",
    "rfc822": "",
    "headers": []
}


class AllowedTagsSanitizer(sanitizer.HTMLSanitizer):

    def sanitize_token(self, token):
        if 'name' not in token:
            # allow non-elements
            return super(AllowedTagsSanitizer, self).sanitize_token(token)
        else:
            if token['name'] in self.allowed_elements:
                return super(AllowedTagsSanitizer, self).sanitize_token(token)


def clean_html(buf):
    """Cleans HTML of dangerous tags and content."""
    buf = buf.strip()
    if not buf:
        return buf

    html_parser = html5lib.HTMLParser(tree=treebuilders.getTreeBuilder("dom"),
                                      tokenizer=AllowedTagsSanitizer)
    html_parser.tokenizer_class._allowed_tags = None
    dom_tree = html_parser.parseFragment(buf)

    walker = treewalkers.getTreeWalker("dom")
    stream = walker(dom_tree)

    s = serializer.htmlserializer.HTMLSerializer(omit_optional_tags=False,
                                                 quote_attr_values=True)
    return s.render(stream, 'utf-8')


def get_raw_body_text(msg):
    raw_body = []

    if not msg.is_multipart():
        # Treat text document attachments as belonging to the body of the mail.
        # Attachments with a file-extension of .htm/.html are implicitely
        # treated
        # as text as well in order not to escape later checks (e.g. URL scan).
        if (not 'content-disposition' in msg and
            msg.get_content_maintype() == 'text') or\
                (msg.get_filename('').lower().endswith('.html') or
                 msg.get_filename('').lower().endswith('.htm')):
            encoding = msg.get_content_charset()

            raw_body_str = msg.get_payload(decode=True)
            content_type = msg.get_content_subtype()

            raw_body.append((encoding, raw_body_str, content_type))
    else:
        for part in msg.get_payload():
            raw_body.extend(get_raw_body_text(part))

    return raw_body


def get_file_extension(filename):
    extension = ''
    dot_idx = filename.rfind('.')

    if dot_idx != -1:
        extension = filename[dot_idx + 1:]

    return extension


def get_file_hashes(data):
    hashalgo = ['md5', 'sha1', 'sha256', 'sha384', 'sha512']
    hashes = {}

    for k in hashalgo:
        ha = getattr(hashlib, k)
        h = ha()
        h.update(data)
        hashes[k] = h.hexdigest()

    return hashes


def traverse_multipart(msg, counter=0, include_attachment_data=False):
    attachments = {}

    if msg.is_multipart():
        for part in msg.get_payload():
            attachments.update(
                traverse_multipart(part, counter, include_attachment_data))
    else:
        lower_keys = dict((k.lower(), v) for k, v in msg.items())

        if 'content-disposition' in lower_keys or\
                not msg.get_content_maintype() == 'text':
            # if it's an attachment-type, pull out the filename
            # and calculate the size in bytes
            data = msg.get_payload(decode=True)
            file_size = len(data)

            filename = msg.get_filename('')
            if filename == '':
                filename = 'part-%03d' % (counter)
            else:
                filename = decode_field(filename, force=True)

            extension = get_file_extension(filename)
            hashes = get_file_hashes(data)

            file_id = str(uuid.uuid1())
            attachments[file_id] = {}
            attachments[file_id]['filename'] = filename
            attachments[file_id]['size'] = file_size
            attachments[file_id]['extension'] = extension
            attachments[file_id]['hashes'] = hashes

            if magic:
                attachments[file_id]['mime-type'] = magic.from_buffer(
                    data, mime=True).decode('utf-8')
            else:
                attachments[file_id]['mime-type'] = 'undetermined'

            if include_attachment_data:
                attachments[file_id]['raw'] = base64.b64encode(data)

            counter += 1

    return attachments


def force_string_decode(string):

    if string is None:
        return ''

    encodings = ('latin1', 'utf-8', 'koi8-r', 'koi8-u', 'windows-1251')
    text = ''

    encoding = chardet.detect(string).get('encoding')

    if encoding:
        text = string.decode(encoding, 'ignore')
    else:

        for e in encodings:
            try:
                test = string.decode(e)
                text = test
                break
            except UnicodeDecodeError:
                pass

        if text == '':
            text = string.decode('ascii', 'ignore')

    return text


def decode_field(field, force=False):
    '''Try to get the specified field using the Header module.
       If there is also an associated encoding, try to decode the
       field and return it, else return a specified default value.'''
    text = field

    if not (isinstance(field, unicode)):
        encoding = chardet.detect(field).get('encoding')
        if encoding:
            field = field.decode(encoding, 'ignore')

    if isinstance(field, unicode):
        pre_field = field.encode('utf-8')
    else:
        pre_field = field

    try:
        _decoded = email.Header.decode_header(pre_field)
    except email.errors.HeaderParseError:
        return field

    out_text = []

    regex = '(=\\?(.+)\\?([bBqQ])\\?(.+\\?=))'

    for element in _decoded:

        _text, charset = element

        if charset:
            try:
                out_text.append(_text.decode(charset, 'ignore'))
            except UnicodeDecodeError:
                if force and sys.version_info < (3, 0):
                    out_text.append(force_string_decode(_text))
        else:
            for chunk in _text.split():
                m = re.search(regex, chunk)

                if m and m.group(0):
                    encoding = m.group(2)
                    type_coding = m.group(3)
                    b64_text = m.group(4)

                    if type_coding.lower() == 'b':
                        decoded_text = base64.b64decode(b64_text)

                    elif type_coding.lower() == 'q':
                        decoded_text = quopri.decodestring(b64_text)

                    if encoding:
                        decoded_text = decoded_text.decode(encoding, 'ignore')

                    else:
                        decoded_text = force_string_decode(decoded_text)

                    chunk = _text.replace(m.group(1), decoded_text)
                    out_text.append(chunk)
                else:
                    decoded_text = force_string_decode(chunk)
                    out_text.append(decoded_text)

    text = u" ".join(out_text)

    return text


def decode_email(eml_file, include_raw_body=False,
                 include_attachment_data=False):
    fp = open(eml_file)
    msg = email.message_from_file(fp)
    fp.close()
    return parse_email(msg, include_raw_body, include_attachment_data)


def decode_email_s(eml_file, include_raw_body=False,
                   include_attachment_data=False):
    msg = email.message_from_string(eml_file)

    if include_attachment_data:
        global_maula['rfc822'] = eml_file

    return parse_email(msg, include_raw_body, include_attachment_data)


def parse_email(msg, include_raw_body=False, include_attachment_data=False):
    maila = global_maula.copy()

    # parse and decode subject
    subject = msg.get('subject', '')
    maila['subject'] = decode_field(subject)

    # messageid
    maila['message_id'] = msg.get('message-id', '')

    headers = msg.items()

    for header in headers:
        maila['headers'].append((header[0], decode_field(header[1])))

    # parse and decode from
    # @TODO verify if this hack is necessary for other e-mail fields as well
    m = email_regex.search(msg.get('from', '').lower())
    if m:
        maila['from'] = m.group(1)
    else:
        from_ = email.utils.parseaddr(msg.get('from', '').lower())
        maila['from'] = from_[1]

    # parse and decode to
    to = email.utils.getaddresses(msg.get_all('to', []))
    maila['to'] = []
    for m in to:
        if not m[1] == '':
            maila['to'].append("%s <%s>" %
                               (decode_field(m[0]), decode_field(m[1])))

    # parse and decode Cc
    cc = email.utils.getaddresses(msg.get_all('cc', []))
    maila['cc'] = []
    for m in cc:
        if not m[1] == '':
            maila['cc'].append("%s <%s>" %
                               (decode_field(m[0]), decode_field(m[1])))

    # parse and decode Date
    # "." -> ":" replacement is for fixing bad clients (e.g. outlook express)
    msg_date = msg.get('date')
    try:
        msg_date.replace('.', ':')
    except AttributeError:
        pass

    if msg_date:

        try:
            date_ = dateutil.parser.parse(msg_date)
        except:
            date_ = email.utils.parsedate_tz(msg_date)

            if date_:

                if not date_[9] is None:
                    tzinfo = dateutil.tz.tzoffset(None, date_[9])
                else:
                    tzinfo = dateutil.tz.tzutc()

                date_ = datetime.datetime.fromtimestamp(
                    email.utils.mktime_tz(date_))
                if date_.tzname() is None:
                    date_ = date_.replace(tzinfo=tzinfo)
    else:
        date_ = dateutil.parser.parse('1970-01-01 00:00:00 +0000')

    maila['date'] = date_

    # sender ip
    maila['x-originating-ip'] = msg.get('x-originating-ip', '').strip('[]')

    # mail receiver path / parse any domain, e-mail
    # @TODO parse case where domain is specified but in parantheses only an IP
    maila['received'] = []
    maila['received_raw'] = []
    maila['received_emails'] = []
    maila['received_domains'] = []

    try:

        for l in msg.get_all('received'):
            l = re.sub(r'(\r|\n|\s|\t)+', ' ', l.lower())
            maila['received_raw'].append(l)

            # search for domains / e-mail addresses
            for m in domain_regex.findall(l):
                checks = True
                if '.' in m:
                    try:
                        int(re.sub(r'[.-]', '', m))

                        if not ipv4_regex.match(m) or m == '127.0.0.1':
                            checks = False
                    except ValueError:
                        pass

                if checks:
                    maila['received_domains'].append(m)

            m = email_regex.findall(l)
            if m:
                maila['received_emails'] += m

            # ----------------------------------------------

            # try to parse received lines and normalize them
            try:
                f, b = l.split('by')
                b, undef = b.split('for')
            except:
                continue

            b_d = b_d_regex.search(b)
            f_d = f_d_regex.search(f)
            for_d = for_d_regex.search(l)

            if for_d:
                maila['to'].append(for_d.group(1))
                maila['to'] = list(set(maila['to']))

            if f_d:
                if not f_d.group(2):
                    f_d_2 = ''
                else:
                    f_d_2 = f_d.group(2)
                if not f_d.group(3):
                    f_d_3 = ''
                else:
                    f_d_3 = f_d.group(3)

                f = '{0} ({1} [{2}])'.format(f_d.group(1), f_d_2, f_d_3)

                if b_d is None:
                    b = ''
                else:
                    b = b_d.group(1)

                maila['received'].append([f, b])
    except:
        pass

    maila['received_emails'] = list(set(maila['received_emails']))
    maila['received_domains'] = list(set(maila['received_domains']))

    # get raw header
    raw_body = get_raw_body_text(msg)

    # parse any URLs found in the body
    list_observed_urls = []
    maila['body'] = {}

    for body_tup in raw_body:
        encoding, body, content_type = body_tup

        if not body:
            continue

        if sys.version_info >= (3, 0) and (isinstance(body, bytes) or
                                           isinstance(body, bytearray)):
            body = body.decode('utf-8', 'ignore')
        else:
            pass
            # Unicode codepoint sequences that resemble UTF-8 sequences.
            # p = re.compile(ur'''(?x)
            # \xF0[\x90-\xBF][\x80-\xBF]{2} |  # Valid 4-byte sequences
            #         [\xF1-\xF3][\x80-\xBF]{3} |
            #     \xF4[\x80-\x8F][\x80-\xBF]{2} |

            # \xE0[\xA0-\xBF][\x80-\xBF]    |  # Valid 3-byte sequences
            #         [\xE1-\xEC][\x80-\xBF]{2} |
            #     \xED[\x80-\x9F][\x80-\xBF]    |
            #         [\xEE-\xEF][\x80-\xBF]{2} |

            # [\xC2-\xDF][\x80-\xBF]           # Valid 2-byte sequences
            #     ''')

            # body = p.sub(
            #     lambda m: ''.join([chr(ord(i)) for i in
            #                        m.group(0)]), body)

        if not encoding:
            try:
                encoding = chardet.detect(body).get('encoding')
            except:
                pass

        if encoding:
            try:
                body = body.decode(encoding, 'ignore')
                raw_body = body.decode(encoding, 'ignore')
            except UnicodeEncodeError:
                # это уже utf-8
                pass

        if content_type == 'html':
            try:
                body = clean_html(body)
            except UnicodeDecodeError:
                # Не удалоось очистить html
                pass

        maila['body'][content_type] = body

        if include_raw_body:
            maila['raw_body'][content_type] = raw_body
        else:
            maila['raw_body'] = []

        for match in url_regex_simple.findall(body):
            found_url = match[0].replace('hxxp', 'http')
            try:
                found_url = urlparse(found_url).geturl()
            except ValueError:
                pass

            # let's try to be smart by stripping of noisy bogus parts
            found_url = re.split(r'''[\', ", \,, \), \}, \\]''', found_url)[0]

            if found_url not in list_observed_urls:
                list_observed_urls.append(found_url)

    maila['urls'] = list_observed_urls

    # parse attachments
    maila['attachments'] = traverse_multipart(msg, 0, include_attachment_data)

    return maila


def main():
    opts, args = getopt.getopt(sys.argv[1:], 'i:')
    msgfile = None

    for o, k in opts:
        if o == '-i':
            msgfile = k

    m = decode_email(msgfile)
    print m
    print
    print m['date'].isoformat()
    # print decode_email(msgfile, include_raw_body=True,
    # include_attachment_data=True)


if __name__ == '__main__':
    main()
