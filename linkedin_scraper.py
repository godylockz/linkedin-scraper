#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
LinkedInScapper: Automatically extracts and analyzes LinkedIn profile data from HTTP responses
"""

from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, FlowLayout
from java.awt.event import ActionListener
from javax.swing import JPanel, JScrollPane, JTextArea, JButton, JLabel, JCheckBox, JTextField
from javax.swing import JTable, JFrame, JFileChooser, JSplitPane, JTabbedPane, JMenuItem
from javax.swing.table import DefaultTableModel
from java.io import File
import json
import csv
import io
import os
import re
from datetime import datetime


class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):

    def __init__(self):
        self.profiles = []
        self._seen_profiles = set()
        self.auto_extract = True
        self.save_to_file = False
        self.output_directory = ""
        self.debug_enabled = False

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Set extension name
        callbacks.setExtensionName("LinkedInScapper")

        # Create the GUI
        self._create_gui()

        # Listeners can fire immediately, so initialize the UI first.
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        # Replay existing proxy history to populate profiles on reload
        self._replay_proxy_history()

        print("[LinkedInScapper] Extension loaded successfully (SDUI diagnostics v3)!")

    def _get_profile_key(self, profile):
        """Return a unique key for a profile to detect duplicates"""
        url = profile.get("profile_url", "")
        if url:
            # Normalize: strip query params and trailing slashes
            url = url.split("?")[0].rstrip("/")
            return url
        # Fallback to name + position if no URL
        return (profile.get("name", "") + "|" + profile.get("position", "")).lower()

    def _add_profile(self, profile):
        """Add a profile if not already seen. Returns True if added."""
        key = self._get_profile_key(profile)
        if key in self._seen_profiles:
            return False
        self._seen_profiles.add(key)
        self.profiles.append(profile)
        self._table_model.addRow(
            [profile.get("name", "N/A"), profile.get("position", "N/A"), profile.get("location", "N/A"), profile.get("profile_url", "N/A"), profile.get("company_id", "N/A"), profile.get("badge", "N/A"), profile.get("timestamp", "N/A")]
        )
        return True

    @staticmethod
    def _url_decode(value):
        return re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), value)

    def _company_id(self, message, response_text):
        """The company filter behind a search, so rows can be traced to it.

        Read from the request's currentCompany filter, falling back to the
        filter echoed in the response for manually selected messages.
        """
        try:
            query = str(self._helpers.analyzeRequest(message).getUrl().getQuery() or "")
        except Exception:
            query = ""
        match = re.search(r"currentCompany=([^&]*)", query)
        if match:
            ids = re.findall(r"\d+", self._url_decode(match.group(1)))
            if ids:
                return ",".join(ids)
        match = re.search(
            r'\\?"filterKey\\?"\s*:\s*\\?"currentCompany\\?"\s*,\s*\\?"filterList\\?"\s*:\s*\[([^\]]*)\]',
            response_text or "")
        if match:
            ids = re.findall(r"\d+", match.group(1))
            if ids:
                return ",".join(ids)
        return ""

    def _annotate_profiles(self, profiles, message=None, response_text=""):
        """Stamp every profile from one response with its time and company filter."""
        company_id = self._company_id(message, response_text) if (message or response_text) else ""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for profile in profiles:
            profile["timestamp"] = timestamp
            if company_id:
                profile["company_id"] = company_id
        return profiles

    def _replay_proxy_history(self):
        """Scan existing Burp proxy history for LinkedIn traffic to populate profiles on reload"""
        print("[LinkedInScapper] Replaying proxy history...")
        proxy_history = self._callbacks.getProxyHistory()
        if not proxy_history:
            print("[LinkedInScapper] No proxy history found")
            return

        count = 0
        for item in proxy_history:
            request = item.getRequest()
            response = item.getResponse()
            if not request or not response:
                continue

            request_str = self._helpers.bytesToString(request)

            if not self._is_supported_request(item):
                continue

            response_str = self._helpers.bytesToString(response)
            profiles = self._extract_profiles_from_response(response_str)
            print("[LinkedInScapper] Replay: {} profiles from {}".format(len(profiles), self._helpers.analyzeRequest(item).getUrl().getPath()))

            for profile in self._annotate_profiles(profiles, item, response_str):
                if self._add_profile(profile):
                    count += 1

        self._stats_label.setText("Profiles extracted: " + str(len(self.profiles)))
        print("[LinkedInScapper] Replayed proxy history: recovered {} profiles".format(count))

    def _create_gui(self):
        # Main panel
        self._main_panel = JPanel(BorderLayout())

        # Create tabbed pane
        self._tabbed_pane = JTabbedPane()

        # Profiles tab
        self._profiles_tab = self._create_profiles_tab()
        self._tabbed_pane.addTab("Extracted Profiles", self._profiles_tab)

        # Settings tab
        self._settings_tab = self._create_settings_tab()
        self._tabbed_pane.addTab("Settings", self._settings_tab)

        # About tab
        self._about_tab = self._create_about_tab()
        self._tabbed_pane.addTab("About", self._about_tab)

        self._main_panel.add(self._tabbed_pane, BorderLayout.CENTER)

    def _create_profiles_tab(self):
        panel = JPanel(BorderLayout())

        # Control panel
        control_panel = JPanel(FlowLayout(FlowLayout.LEFT))

        # Clear button
        clear_button = JButton("Clear All", actionPerformed=self._clear_profiles)
        control_panel.add(clear_button)

        # Export button
        export_button = JButton("Export to CSV", actionPerformed=self._export_profiles)
        control_panel.add(export_button)

        # Stats label
        self._stats_label = JLabel("Profiles extracted: 0")
        control_panel.add(self._stats_label)

        panel.add(control_panel, BorderLayout.NORTH)

        # Create table for profiles
        self._table_model = DefaultTableModel()
        self._table_model.setColumnIdentifiers(["Name", "Position", "Location", "Profile URL", "Company ID", "Badge", "Timestamp"])

        self._profiles_table = JTable(self._table_model)
        self._profiles_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)

        # Add table to scroll pane
        scroll_pane = JScrollPane(self._profiles_table)
        panel.add(scroll_pane, BorderLayout.CENTER)

        return panel

    def _create_settings_tab(self):
        panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST

        # Auto-extract checkbox
        gbc.gridx = 0
        gbc.gridy = 0
        panel.add(JLabel("Auto-extract profiles:"), gbc)

        gbc.gridx = 1
        self._auto_extract_checkbox = JCheckBox("", self.auto_extract)
        panel.add(self._auto_extract_checkbox, gbc)

        # Auto-save checkbox
        gbc.gridx = 0
        gbc.gridy = 1
        panel.add(JLabel("Auto-save to file:"), gbc)

        gbc.gridx = 1
        self._auto_save_checkbox = JCheckBox("", self.save_to_file)
        panel.add(self._auto_save_checkbox, gbc)

        # Debug checkbox
        gbc.gridx = 0
        gbc.gridy = 3
        panel.add(JLabel("Enable debug logging:"), gbc)

        gbc.gridx = 1
        gbc.fill = GridBagConstraints.NONE
        self._debug_checkbox = JCheckBox("", self.debug_enabled)
        panel.add(self._debug_checkbox, gbc)

        # Output directory
        gbc.gridx = 0
        gbc.gridy = 4
        panel.add(JLabel("Output directory:"), gbc)

        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self._output_dir_field = JTextField(20)
        panel.add(self._output_dir_field, gbc)

        gbc.gridx = 2
        gbc.fill = GridBagConstraints.NONE
        browse_button = JButton("Browse", actionPerformed=self._browse_directory)
        panel.add(browse_button, gbc)

        return panel

    def _create_about_tab(self):
        panel = JPanel(BorderLayout())

        about_text = """
LinkedInScapper - LinkedIn Profile Extractor

A Burp Suite extension for red team operators and security researchers to automatically 
extract and analyze LinkedIn profile data from HTTP responses during reconnaissance activities.

Features:
• Automatic profile extraction from LinkedIn API responses
• Real-time monitoring of LinkedIn traffic
• CSV export functionality  
• Configurable auto-save options
• Clean, organized profile data presentation

Usage:
1. Enable the extension in Burp Suite
2. Configure settings in the Settings tab
3. Browse LinkedIn or use other tools to generate traffic
4. View extracted profiles in the Profiles tab
5. Export data as needed for further analysis

Author: @two06
        """

        text_area = JTextArea(about_text)
        text_area.setEditable(False)
        text_area.setLineWrap(True)
        text_area.setWrapStyleWord(True)

        scroll_pane = JScrollPane(text_area)
        panel.add(scroll_pane, BorderLayout.CENTER)

        return panel

    def _debug_log(self, message):
        """Log debug messages only if debug is enabled"""
        if self._debug_checkbox.isSelected():
            print(message)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only process responses
        if messageIsRequest:
            return

        # Check if auto-extract is enabled
        if not self._auto_extract_checkbox.isSelected():
            return

        # Get the response
        response = messageInfo.getResponse()
        if not response:
            return

        # Get the request URL for debugging
        request = messageInfo.getRequest()
        request_str = self._helpers.bytesToString(request)

        # Convert response to string
        response_str = self._helpers.bytesToString(response)

        # Debug: Check for LinkedIn URLs
        if "linkedin.com" in request_str.lower():
            self._debug_log("[LinkedInScapper] DEBUG: LinkedIn request detected")
            self._debug_log("[LinkedInScapper] DEBUG: Request URL contains: " + request_str.split("\n")[0])

        if not self._is_supported_request(messageInfo):
            return

        # Debug: Check response content
        if "included" in response_str:
            self._debug_log("[LinkedInScapper] DEBUG: Response contains 'included' array")
        if "EntityResultViewModel" in response_str:
            self._debug_log("[LinkedInScapper] DEBUG: Response contains EntityResultViewModel")

        # Extract profiles from the response
        profiles = self._extract_profiles_from_response(response_str)

        if profiles:
            print("[LinkedInScapper] SUCCESS: Found {} profiles".format(len(profiles)))
            added = 0
            for profile in self._annotate_profiles(profiles, messageInfo, response_str):
                if self._add_profile(profile):
                    added += 1

            if added > 0:
                # Update stats
                self._stats_label.setText("Profiles extracted: " + str(len(self.profiles)))

                # Auto-save if enabled
                if self._auto_save_checkbox.isSelected():
                    self._auto_save_profiles()

            print("[LinkedInScapper] Extracted {} new profiles ({} duplicates skipped)".format(added, len(profiles) - added))
        else:
            self._debug_log("[LinkedInScapper] DEBUG: No profiles found in response")

    def _is_supported_request(self, message):
        """Use the actual URL, rather than matching arbitrary header values."""
        url = self._helpers.analyzeRequest(message).getUrl()
        host = str(url.getHost()).lower()
        path = str(url.getPath())
        if path.startswith("/flagship-web/"):
            path = path[len("/flagship-web"):]
        return (host == "linkedin.com" or host.endswith(".linkedin.com")) and (
            path.startswith("/voyager/api/") or
            path.rstrip("/") == "/search/results/people" or
            path.startswith("/rsc-action/") or
            "/api/" in path
        )

    @staticmethod
    def _slice_bracketed(text, start):
        """Return the substring of a JSON array/object starting at `start`."""
        opener = text[start]
        closer = {"[": "]", "{": "}"}[opener]
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == "\\" and in_string:
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        return None

    def _extract_rehydration_flight(self, body):
        """Recover the Flight stream embedded in a server-rendered search page.

        /search/results/people/ returns HTML, not a Flight stream: the rows are
        JSON-escaped inside `window.__como_rehydration__ = [ ... ]` and split
        across chunks at arbitrary offsets, so the chunks are concatenated
        before the row parser sees them.
        """
        idx = body.find("window.__como_rehydration__")
        if idx == -1:
            return None
        start = body.find("[", idx)
        if start == -1:
            return None
        literal = self._slice_bracketed(body, start)
        if literal is None:
            self._debug_log("[LinkedInScapper] Rehydration payload is truncated")
            return None
        try:
            chunks = json.loads(literal)
        except ValueError:
            self._debug_log("[LinkedInScapper] Rehydration payload is not valid JSON")
            return None
        stream = "".join(c for c in chunks if isinstance(c, (str, unicode)))
        self._debug_log("[LinkedInScapper] Rehydration: {} chunks, {} chars".format(len(chunks), len(stream)))
        return stream

    def _extract_flight_profiles(self, body):
        """Read the JSON model rows of a captured SDUI Flight stream.

        Module rows are ignored. Resolve model references lazily, with cycle
        protection; only visible children are traversed, never action payloads.
        """
        records = {}
        invalid_rows = 0
        for line in body.split("\n"):
            line = line.rstrip("\r")
            match = re.match(r"^([0-9a-f]+):([\[{].*)$", line)
            if match:
                try:
                    records[match.group(1)] = json.loads(match.group(2))
                except ValueError:
                    invalid_rows += 1
                    continue
        self._debug_log("[LinkedInScapper] Flight: {} model rows, {} invalid rows".format(len(records), invalid_rows))

        def resolve(value, seen=None):
            seen = set() if seen is None else seen
            while isinstance(value, (str, unicode)):
                match = re.match(r"^\$(?:L)?([0-9a-f]+)(?::(.*))?$", value)
                if not match or value in seen:
                    return None
                seen.add(value)
                value = records.get(match.group(1))
                for part in (match.group(2) or "").split(":"):
                    if not part:
                        continue
                    value = resolve(value, seen) if isinstance(value, (str, unicode)) and value.startswith("$") else value
                    if isinstance(value, list):
                        if part == "props" and len(value) == 4 and value[0] == "$":
                            value = value[3]
                        elif part.isdigit() and int(part) < len(value):
                            value = value[int(part)]
                        else:
                            return None
                    elif isinstance(value, dict):
                        value = value.get(part)
                    else:
                        return None
                if not isinstance(value, (str, unicode)) or not value.startswith("$"):
                    return value
            return value

        def walk(value, ancestors=None):
            ancestors = set() if ancestors is None else ancestors
            if isinstance(value, (str, unicode)) and value.startswith("$"):
                value = resolve(value)
            if not isinstance(value, (list, dict)) or id(value) in ancestors:
                return
            ancestors = ancestors | set([id(value)])
            if isinstance(value, list):
                if len(value) == 4 and value[0] == "$" and isinstance(value[3], dict):
                    props = value[3]
                    yield props
                    for child in walk(props.get("children"), ancestors):
                        yield child
                    text_props = resolve(props.get("textProps"))
                    if isinstance(text_props, dict):
                        for child in walk(text_props.get("children"), ancestors):
                            yield child
                else:
                    for item in value:
                        for child in walk(item, ancestors):
                            yield child

            elif isinstance(value, dict):
                # Flight layouts and server responses can hold components inline
                # instead of assigning them their own model row.
                children = []
                if "layoutId" in value:
                    children.append(value.get("component"))
                response = value.get("response")
                if isinstance(response, dict):
                    completion = response.get("completionAction", {})
                    if isinstance(completion, dict):
                        for action in completion.get("actions", []):
                            if isinstance(action, dict) and action.get("$type") == "proto.sdui.actions.core.ReplaceComponent":
                                content = action.get("value", {}).get("content", {})
                                if isinstance(content, dict):
                                    children.append(content.get("newComponent"))
                for item in children:
                    for child in walk(item, ancestors):
                        yield child

        def text(value, ancestors=None):
            ancestors = set() if ancestors is None else ancestors
            if isinstance(value, (str, unicode)):
                if value.startswith("$$"):
                    return value[1:]
                if not value.startswith("$"):
                    return value
                value = resolve(value)
            if not isinstance(value, (list, dict)) or id(value) in ancestors:
                return ""
            ancestors = ancestors | set([id(value)])
            if isinstance(value, list):
                if len(value) == 4 and value[0] == "$" and isinstance(value[3], dict):
                    return text(value[3].get("children"), ancestors)
                return "".join(text(item, ancestors) for item in value)
            return text(value.get("children"), ancestors)

        def profile_url(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key == "url" and isinstance(child, (str, unicode)):
                        if child.startswith("/in/"):
                            return "https://www.linkedin.com" + child
                        if child.startswith("https://www.linkedin.com/in/"):
                            return child
                    found = profile_url(child)
                    if found:
                        return found
            elif isinstance(value, list):
                for child in value:
                    found = profile_url(child)
                    if found:
                        return found
            return ""

        profiles = []
        seen = set()
        cards_found = titles_found = links_found = 0
        visited_cards = set()
        for record in records.values():
            for card in walk(record):
                tracking = resolve(card.get("viewTrackingSpecs"))
                if not isinstance(tracking, dict) or tracking.get("viewName") != "people-search-result":
                    continue
                if id(card) in visited_cards:
                    continue
                visited_cards.add(id(card))
                cards_found += 1
                nodes = list(walk(card.get("children")))
                title = None
                for node in nodes:
                    spec = resolve(node.get("viewTrackingSpecs"))
                    if isinstance(spec, dict) and spec.get("viewName") == "search-result-lockup-title":
                        title = node
                        break
                if title is None:
                    continue
                titles_found += 1
                title_nodes = list(walk(title.get("children")))
                link = next((node for node in title_nodes if profile_url(node.get("action"))), None)
                if link is None:
                    continue  # Includes anonymous "LinkedIn Member" cards.
                links_found += 1
                name = text(link.get("children")).strip()
                url = profile_url(link.get("action"))
                if not name or name == "LinkedIn Member" or url in seen:
                    continue
                seen.add(url)
                # The lockup's headline and location precede snippets/social proof.
                subtitles = []
                for node in nodes:
                    tp = resolve(node.get("textProps"))
                    if isinstance(tp, dict) and tp.get("fontSize") == "small" and node.get("maxLineCountExpression") == 2:
                        subtitles.append(text(tp.get("children")))
                profile = {"name": name, "profile_url": url}
                if subtitles:
                    profile["position"] = subtitles[0]
                if len(subtitles) > 1:
                    profile["location"] = subtitles[1]
                if any(node.get("aria-label") == "Verified" for node in title_nodes):
                    profile["badge"] = "Verified"
                profiles.append(profile)
        if not profiles:
            print("[LinkedInScapper] Flight counts: rows={}, invalid={}, result_markers={}, cards={}, titles={}, links={}".format(
                len(records), invalid_rows, body.count('"people-search-result"'), cards_found, titles_found, links_found))
        return profiles

    @staticmethod
    def _fix_encoding(text):
        """Re-encode a Burp ISO-8859-1 string back to bytes and decode as UTF-8"""
        try:
            # Burp's bytesToString uses ISO-8859-1, so reverse that to get raw bytes
            raw = text.encode("iso-8859-1")
            return raw.decode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return text

    def _extract_json_body(self, response_text):
        """Extract the JSON body from a full HTTP response, handling headers and trailing data"""
        # Split headers from body on the double CRLF boundary
        body = response_text
        for separator in ["\r\n\r\n", "\n\n"]:
            idx = response_text.find(separator)
            if idx != -1:
                body = response_text[idx + len(separator) :]
                break

        # Fix Burp's ISO-8859-1 mangling before JSON parsing
        body = self._fix_encoding(body)

        # Find the first '{' in the body
        json_start = body.find("{")
        if json_start == -1:
            return None

        body = body[json_start:]

        # Try parsing as-is first
        try:
            return json.loads(body)
        except ValueError:
            pass

        # If that fails, find the matching closing brace to ignore trailing data
        depth = 0
        in_string = False
        escape = False
        for i, ch in enumerate(body):
            if escape:
                escape = False
                continue
            if ch == "\\" and in_string:
                escape = True
                continue
            if ch == '"' and not escape:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(body[: i + 1])
                    except ValueError:
                        return None
        return None

    def _extract_profiles_from_response(self, response_text):
        """Extract profile information from LinkedIn response"""
        profiles = []

        body = response_text
        if body.startswith("HTTP/"):
            body = re.split(r"\r?\n\r?\n", body, maxsplit=1)[-1]
        body = self._fix_encoding(body)
        rehydration = self._extract_rehydration_flight(body)
        if rehydration is not None:
            body = rehydration
        if re.search(r"(?m)^[0-9a-f]+:(?:I?\[|\{)", body):
            try:
                profiles = self._extract_flight_profiles(body)
                if not profiles:
                    if '"people-search-result"' not in body and (
                        '"relationship-building-button"' in body or
                        '"edge-creation-connect-action"' in body
                    ):
                        print("[LinkedInScapper] SDUI button response: no full result cards. Extract the /search/results/people/ response for names, headlines and locations.")
                    else:
                        print("[LinkedInScapper] Flight response: 0 profiles extracted (see Flight counts above).")
                return profiles
            except Exception:
                import traceback
                print("[LinkedInScapper] Flight parser failed:\n" + traceback.format_exc())
                return []

        json_data = self._extract_json_body(response_text)
        if json_data is None:
            self._debug_log("[LinkedInScapper] DEBUG: No valid JSON found in response")
            return profiles

        try:
            self._debug_log("[LinkedInScapper] DEBUG: JSON parsed successfully")

            # Check for different possible structures
            included_items = json_data.get("included", [])
            if not included_items:
                # Try alternative structures
                data_items = json_data.get("data", {})
                if isinstance(data_items, dict):
                    # Look for searchDashClustersByAll or similar
                    search_results = data_items.get("searchDashClustersByAll", {})
                    if search_results:
                        elements = search_results.get("elements", [])
                        for element in elements:
                            items = element.get("items", [])
                            included_items.extend(items)

                # Try looking for elements directly
                if not included_items:
                    elements = json_data.get("elements", [])
                    included_items.extend(elements)

            self._debug_log("[LinkedInScapper] DEBUG: Found {} items to process".format(len(included_items)))

            # Extract profiles from included array
            for item in included_items:
                if not isinstance(item, dict):
                    continue

                # Look for different profile indicators
                item_type = item.get("$type", "")
                if any(indicator in item_type for indicator in ["EntityResultViewModel", "ProfileViewModel", "Person", "SearchHit"]):
                    self._debug_log("[LinkedInScapper] DEBUG: Found potential profile item: " + item_type)
                    profile_data = self._extract_profile_data(item)
                    if profile_data and profile_data.get("name"):
                        profiles.append(profile_data)
                        self._debug_log("[LinkedInScapper] DEBUG: Extracted profile: " + profile_data.get("name", "Unknown"))

        except Exception as e:
            print("[LinkedInScapper] ERROR: Error parsing JSON: " + str(e))
            # Try to save problematic response for debugging
            try:
                with open("/tmp/LinkedInScapper_debug.json", "w") as f:
                    f.write(response_text[json_start : json_start + 1000])  # First 1000 chars
            except:
                pass

        return profiles

    @staticmethod
    def _as_text(value):
        """Coerce any cell value to text without an implicit ASCII encode."""
        if value is None:
            return u""
        if isinstance(value, unicode):
            return value
        if isinstance(value, bytes):
            return value.decode("utf-8", "replace")
        return unicode(value)

    def _extract_profile_data(self, item):
        """Extract profile data from a single item"""
        profile_data = {}

        # Extract name - try multiple possible fields
        name = None
        if "title" in item and isinstance(item["title"], dict) and "text" in item["title"]:
            name = item["title"]["text"]
        elif "headline" in item and isinstance(item["headline"], dict):
            name = item["headline"].get("text", "")
        elif "name" in item:
            if isinstance(item["name"], dict):
                name = item["name"].get("text", item["name"].get("value", ""))
            else:
                name = str(item["name"])
        elif "fullName" in item:
            name = item["fullName"]

        if name and name != "LinkedIn Member" and len(name.strip()) > 0:
            profile_data["name"] = name.strip()
        else:
            return None  # Skip if no valid name

        # Extract position - try multiple fields
        if "primarySubtitle" in item and isinstance(item["primarySubtitle"], dict) and "text" in item["primarySubtitle"]:
            profile_data["position"] = item["primarySubtitle"]["text"]
        elif "headline" in item and isinstance(item["headline"], dict) and "text" in item["headline"]:
            profile_data["position"] = item["headline"]["text"]
        elif "occupation" in item:
            profile_data["position"] = item["occupation"]

        # Extract location
        if "secondarySubtitle" in item and isinstance(item["secondarySubtitle"], dict) and "text" in item["secondarySubtitle"]:
            profile_data["location"] = item["secondarySubtitle"]["text"]
        elif "location" in item:
            if isinstance(item["location"], dict):
                profile_data["location"] = item["location"].get("name", item["location"].get("text", ""))
            else:
                profile_data["location"] = str(item["location"])

        # Extract profile URL
        if "navigationUrl" in item:
            profile_data["profile_url"] = item["navigationUrl"]
        elif "url" in item:
            profile_data["profile_url"] = item["url"]
        elif "publicIdentifier" in item:
            profile_data["profile_url"] = "https://linkedin.com/in/" + item["publicIdentifier"]

        # Extract badge info
        if "badgeIcon" in item and item["badgeIcon"] and "accessibilityText" in item["badgeIcon"]:
            profile_data["badge"] = item["badgeIcon"]["accessibilityText"]
        elif "premium" in item and item["premium"]:
            profile_data["badge"] = "Premium"

        # Extract summary
        if "summary" in item and item["summary"] and "text" in item["summary"]:
            profile_data["summary"] = item["summary"]["text"]
        elif "snippet" in item:
            profile_data["summary"] = item["snippet"]

        # Extract tracking ID
        if "trackingId" in item:
            profile_data["tracking_id"] = item["trackingId"]
        elif "id" in item:
            profile_data["tracking_id"] = item["id"]

        # Trim only: the CSV export is UTF-8, so accents and quotes are kept
        # here exactly as the Flight parser keeps them.
        for key in profile_data:
            if isinstance(profile_data[key], (str, unicode)):
                profile_data[key] = profile_data[key].strip()

        return profile_data

    def _clear_profiles(self, event):
        """Clear all extracted profiles"""
        self.profiles = []
        self._seen_profiles.clear()
        self._table_model.setRowCount(0)
        self._stats_label.setText("Profiles extracted: 0")
        print("[LinkedInScapper] Cleared all profiles")

    def _export_profiles(self, event):
        """Export profiles to CSV"""
        if not self.profiles:
            print("[LinkedInScapper] No profiles to export")
            return

        # File chooser
        file_chooser = JFileChooser()
        file_chooser.setSelectedFile(File("linkedin_profiles_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".csv"))

        if file_chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = file_chooser.getSelectedFile().getAbsolutePath()
            self._save_profiles_to_file(file_path)

    def _save_profiles_to_file(self, file_path):
        """Save profiles to a UTF-8 CSV file - Jython compatible"""
        try:
            if str is bytes:
                # Jython/Python 2: csv writes bytes, and str() on a name with a
                # curly quote or an accent would raise a UnicodeEncodeError.
                csvfile = open(file_path, "wb")
                encode = lambda value: value.encode("utf-8")
            else:
                csvfile = io.open(file_path, "w", encoding="utf-8", newline="")
                encode = lambda value: value
            try:
                writer = csv.writer(csvfile)
                writer.writerow([encode(h) for h in
                                 [u"Name", u"Position", u"Location", u"Profile URL", u"Company ID", u"Badge", u"Summary", u"Timestamp"]])

                for profile in self.profiles:
                    row = [
                        profile.get("name", ""),
                        profile.get("position", ""),
                        profile.get("location", ""),
                        profile.get("profile_url", ""),
                        profile.get("company_id", ""),
                        profile.get("badge", ""),
                        profile.get("summary", ""),
                        profile.get("timestamp", ""),
                    ]
                    writer.writerow([encode(self._as_text(value)) for value in row])
            finally:
                csvfile.close()

            print("[LinkedInScapper] Exported {} profiles to {}".format(len(self.profiles), file_path))

        except Exception as e:
            print("[LinkedInScapper] Error saving file: " + str(e))

    def _auto_save_profiles(self):
        """Auto-save profiles if directory is set"""
        output_dir = self._output_dir_field.getText()
        if output_dir:
            file_path = os.path.join(output_dir, "linkedin_profiles_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".csv")
            self._save_profiles_to_file(file_path)

    def _browse_directory(self, event):
        """Browse for output directory"""
        file_chooser = JFileChooser()
        file_chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

        if file_chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            self._output_dir_field.setText(file_chooser.getSelectedFile().getAbsolutePath())

    def getTabCaption(self):
        return "LinkedInScapper"

    def getUiComponent(self):
        return self._main_panel

    def createMenuItems(self, invocation):
        """Create context menu items"""
        menu_items = []

        # Only show menu for responses
        if invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
            menu_item = JMenuItem("Extract LinkedIn Profiles", actionPerformed=lambda x: self._extract_from_context(invocation))
            menu_items.append(menu_item)

        return menu_items

    def _extract_from_context(self, invocation):
        """Extract profiles from context menu"""
        messages = invocation.getSelectedMessages()
        if not messages:
            return

        for message in messages:
            response = message.getResponse()
            if response:
                response_str = self._helpers.bytesToString(response)
                profiles = self._extract_profiles_from_response(response_str)

                if profiles:
                    added = 0
                    for profile in self._annotate_profiles(profiles, message, response_str):
                        if self._add_profile(profile):
                            added += 1

                    if added > 0:
                        self._stats_label.setText("Profiles extracted: " + str(len(self.profiles)))
                    print("[LinkedInScapper] Manually extracted {} new profiles ({} duplicates skipped)".format(added, len(profiles) - added))

