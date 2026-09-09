#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Offline parser checks; Burp/Java UI imports are not needed."""
from __future__ import unicode_literals
import io
import os
import json
import re
import unittest

source_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'linkedin_scraper.py')
with io.open(source_path, encoding='utf-8') as source_file:
    source = source_file.read()
# Execute the real extension class, excluding only unavailable Burp/Java imports.
source = re.sub(r'^from (?:burp|java\.[\w.]+|javax\.[\w.]+) import .*$', '', source, flags=re.M)
source = source.replace('class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):', 'class BurpExtender(object):')
namespace = {}
try:
    unicode
except NameError:
    namespace['unicode'] = str
exec(compile(source.encode('utf-8'), source_path, 'exec'), namespace)


def element(props):
    return ['$', '$L7', None, props]


def card(name='Example Person', url='/in/example/', verified=False):
    link = element({'action': {'url': url}, 'children': [name, element({'aria-label': 'Verified', 'children': []})] if verified else [name]})
    title = element({'viewTrackingSpecs': {'viewName': 'search-result-lockup-title'}, 'children': element({'textProps': {'children': [link, ' • 2nd']}})})
    def subtitle(value):
        return element({'maxLineCountExpression': 2, 'textProps': {'fontSize': 'small', 'children': [value]}})
    return element({'viewTrackingSpecs': {'viewName': 'people-search-result'}, 'children': [title, subtitle('Engineer'), subtitle('Montréal'), element({'action': {'url': '/in/mutual/'}, 'children': ['Mutual Person']})]})


def stream(records):
    return 'HTTP/2 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n2:I["module",[],"Screen"]\n' + '\n'.join(k + ':' + json.dumps(v) for k, v in records.items())


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.ext = namespace['BurpExtender']()
        self.ext._debug_log = lambda message: None

    def test_cards_not_mutual_connections(self):
        result = self.ext._extract_profiles_from_response(stream({'a': card(verified=True)}))
        self.assertEqual(result, [{'name': 'Example Person', 'profile_url': 'https://www.linkedin.com/in/example/', 'position': 'Engineer', 'location': 'Montréal', 'badge': 'Verified'}])

    def test_forward_references_and_duplicate_roots(self):
        item = card()
        children = item[3]['children']
        item[3]['children'] = '$Lb'
        result = self.ext._extract_profiles_from_response(stream({'0': ['$La', '$La'], 'a': item, 'b': children}))
        self.assertEqual(len(result), 1)

    def test_property_reference_and_cycle(self):
        item = card()
        item[3]['viewTrackingSpecs'] = '$b:props:viewTrackingSpecs'
        result = self.ext._extract_profiles_from_response(stream({'a': item, 'b': element({'viewTrackingSpecs': {'viewName': 'people-search-result'}}), 'c': ['$Lc']}))
        self.assertEqual(len(result), 1)

    def test_anonymous_and_unrelated_nodes(self):
        self.assertEqual(self.ext._extract_profiles_from_response(stream({'a': card('LinkedIn Member', ''), 'b': element({'children': 'Unrelated'})})), [])

    def test_legacy_json(self):
        result = self.ext._extract_profiles_from_response(json.dumps({'included': [{'$type': 'EntityResultViewModel', 'title': {'text': 'Legacy Person'}, 'navigationUrl': 'https://www.linkedin.com/in/legacy/'}]}))
        self.assertEqual(result[0]['name'], 'Legacy Person')

    def test_unicode_line_separator_inside_json_string(self):
        body = stream({'a': card('Example\u2028Person')}).replace('\\u2028', '\u2028')
        result = self.ext._extract_profiles_from_response(body)
        self.assertEqual(result[0]['name'], 'Example\u2028Person')

    def test_lazy_loaded_buttons_are_diagnosed(self):
        # Reduced shape of the supplied lazyLoadedActionsRequest response.
        button = element({
            'viewTrackingSpecs': {'viewName': 'edge-creation-connect-action'},
            'children': element({
                'buttonProps': {'aria-label': 'Invite Example Person to connect'},
                'triggers': [{'action': {'actions': [{'value': {'requestedArguments': {
                    'payload': {'firstName': 'Example', 'lastName': 'Person',
                                'profileCanonicalUrl': 'https://www.linkedin.com/in/example'}
                }}}]}}]
            })
        })
        self.assertEqual(self.ext._extract_profiles_from_response(stream({'3': [['Connect', button]]})), [])

    def test_layout_envelope(self):
        result = self.ext._extract_profiles_from_response(stream({'0': [{'component': card(), 'layoutId': 'search'}]}))
        self.assertEqual(len(result), 1)

    def test_replacement_envelope(self):
        response = {'response': {'completionAction': {'actions': [{
            '$type': 'proto.sdui.actions.core.ReplaceComponent',
            'value': {'content': {'newComponent': card()}}
        }]}}}
        self.assertEqual(len(self.ext._extract_profiles_from_response(stream({'0': response}))), 1)

    def test_action_payload_is_not_a_result(self):
        response = {'response': {'completionAction': {'actions': [{
            '$type': 'proto.sdui.actions.core.ServerRequest',
            'value': {'requestedArguments': {'payload': {'component': card()}}}
        }]}}}
        self.assertEqual(self.ext._extract_profiles_from_response(stream({'0': response})), [])

    def test_server_rendered_html_page(self):
        # /search/results/people/ returns HTML with the Flight rows escaped
        # inside window.__como_rehydration__, split at arbitrary offsets.
        rows = '2:I["module",[],"Screen"]\n' + 'a:' + json.dumps(card('Renée O\u2019Brien')) + '\n'
        half = len(rows) // 2
        chunks = json.dumps([rows[:half], rows[half:]])
        body = ('HTTP/2 200 OK\r\nContent-Type: text/html\r\n\r\n'
                '<!DOCTYPE html><html><body><div id="root"></div>'
                '<script id="rehydrate-data">window.__como_rehydration__ = ' + chunks + '</script>'
                '<script>window.__como_chunks__ = [];</script></body></html>')
        result = self.ext._extract_profiles_from_response(body)
        self.assertEqual([p['name'] for p in result], ['Renée O\u2019Brien'])
        self.assertEqual(result[0]['location'], 'Montréal')

    def test_html_without_rehydration_payload(self):
        body = 'HTTP/2 200 OK\r\n\r\n<html><body>No profiles here</body></html>'
        self.assertEqual(self.ext._extract_profiles_from_response(body), [])

    def test_csv_export_keeps_unicode(self):
        import csv as csv_module
        import tempfile
        self.ext.profiles = [{'name': 'Renée O\u2019Brien', 'position': '\u201cLead\u201d Engineer',
                              'location': 'Montréal', 'profile_url': 'https://www.linkedin.com/in/x/',
                              'badge': 'Verified', 'timestamp': '2026-01-01 00:00:00'}]
        path = os.path.join(tempfile.mkdtemp(), 'out.csv')
        self.ext._save_profiles_to_file(path)
        with io.open(path, encoding='utf-8') as handle:
            rows = list(csv_module.reader(handle))
        self.assertEqual(rows[0][0], 'Name')
        self.assertEqual(rows[1][:3], ['Renée O\u2019Brien', '\u201cLead\u201d Engineer', 'Montréal'])

    def test_company_id_from_request_and_body(self):
        class Url:
            def getHost(self): return 'www.linkedin.com'
            def getPath(self): return '/search/results/people/'
            def getQuery(self): return 'currentCompany=%5B%226702%22%5D&page=80'
        class Helpers:
            def analyzeRequest(self, message):
                return type('R', (), {'getUrl': staticmethod(lambda: Url())})()
        self.ext._helpers = Helpers()
        self.assertEqual(self.ext._company_id(object(), ''), '6702')
        # Manually selected message with no usable query: fall back to the echoed filter.
        class Bare(Helpers):
            def analyzeRequest(self, message):
                return type('R', (), {'getUrl': staticmethod(lambda: type('U', (), {'getQuery': staticmethod(lambda: None)})())})()
        self.ext._helpers = Bare()
        body = '{\\"filterKey\\":\\"currentCompany\\",\\"filterList\\":[\\"6702\\"]}'
        self.assertEqual(self.ext._company_id(object(), body), '6702')
        self.assertEqual(self.ext._company_id(object(), 'nothing'), '')

    def test_annotation_and_dedup_across_reload(self):
        rows = [{'name': 'A', 'profile_url': 'https://www.linkedin.com/in/a/'}]
        self.ext._helpers = None
        self.ext._table_model = type('M', (), {'addRow': lambda self, row: None})()
        self.ext._annotate_profiles(rows, None, '"filterKey":"currentCompany","filterList":["6702"]')
        self.assertEqual(rows[0]['company_id'], '6702')
        self.assertTrue(rows[0]['timestamp'])
        self.assertTrue(self.ext._add_profile(rows[0]))
        # Same person seen again on a later page / after a reload.
        self.assertFalse(self.ext._add_profile({'name': 'A', 'profile_url': 'https://www.linkedin.com/in/a/?trk=x'}))
        self.assertEqual(len(self.ext.profiles), 1)

    def test_request_filter(self):
        class Url:
            def getHost(self):
                return self.host
            def getPath(self):
                return self.path
        class Request:
            def getUrl(self):
                return url
        class Helpers:
            def analyzeRequest(self, message):
                return Request()
        url = Url()
        self.ext._helpers = Helpers()
        for host, path, expected in [('www.linkedin.com', '/search/results/people/', True), ('www.linkedin.com', '/voyager/api/graphql', True), ('linkedin.com.evil.test', '/voyager/api/graphql', False), ('www.linkedin.com', '/feed/', False), ('www.linkedin.com', '/flagship-web/search/results/people/', True), ('www.linkedin.com', '/flagship-web/rsc-action/actions/server-request', True), ('www.linkedin.com', '/rsc-action/actions/server-request/', True)]:
            url.host, url.path = host, path
            self.assertEqual(self.ext._is_supported_request(None), expected)


if __name__ == '__main__':
    unittest.main()
