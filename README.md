# LinkedIn Scraper

Burp Suite extension (Jython) that automatically extracts and analyzes LinkedIn profile data from HTTP responses.

Supports legacy Voyager JSON, people-search SDUI/React Flight responses
(`application/octet-stream`), and the server-rendered `text/html` page at
`/search/results/people/`, whose Flight rows arrive JSON-escaped and chunk-split
inside `window.__como_rehydration__`; the chunks are rejoined before parsing.
Reload the extension in Burp to replay existing proxy history, or right-click a
response and select **Extract LinkedIn Profiles**. Auto-extraction also handles
new responses while browsing search pages.

Extracted rows carry the `currentCompany` filter of the search they came from
(read from the request query, or from the filter echoed in the response for
manually selected messages) as a **Company ID** column in the table and CSV.
Profiles are deduplicated on the profile URL, ignoring query strings, so
re-reading proxy history on reload does not create duplicates. Export is UTF-8:
names and headlines keep accents and curly quotes rather than being stripped.

The Flight parser reads JSON model records and follows component references to
extract names, headlines, locations, profile URLs, and Verified badges from
people-result cards. Anonymous “LinkedIn Member” cards are skipped. It does not
send requests or paginate automatically. Compressed/raw binary bodies and Flight
record types other than JSON models are not decoded by this parser.

Offline regression checks (Python 3, without Burp UI imports):

```sh
python3 -m unittest discover -s tests -v
```

The extension itself targets Burp's Jython runtime; offline checks do not exercise
the Java UI or HTTP listener integration inside Burp.

For troubleshooting, the load message identifies this build as **SDUI diagnostics
v3**. Enable **Settings → Enable debug logging**, then manually extract a captured
people-search response and inspect the extension's Output/Errors tabs. Every empty Flight extraction reports parsed/invalid model rows and result-marker,
card, title, and profile-link counts. Replay also reports each processed request
path; these diagnostics do not require debug logging.

`/flagship-web/` prefixes are normalized, including search and RSC-action routes.
Cards nested in layout and component-replacement response objects are supported. A
`lazyLoadedActionsRequest` response supplies relationship buttons rather than full
result cards; the extension reports this explicitly instead of silently ignoring
it. Use the preceding people-search response for complete result data.

The same parser tests can also run under Jython 2.7.4:

```sh
java -jar /path/to/jython-standalone-2.7.4.jar -B -m unittest discover -s tests -v
```
