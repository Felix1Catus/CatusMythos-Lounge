"""Regression matrix for named submit controls in crawler-derived GET targets."""
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "skills/webapp-exploit-hunter/scripts/_form_controls.py"
SPEC = importlib.util.spec_from_file_location("form_controls_under_test", MODULE)
form_controls = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(form_controls)


def test_get_targets_preserve_submit_button_and_existing_query():
    data = {"forms": [{
        "url": "https://lab.test/search/?locale=en",
        "method": "GET",
        "inputs": [
            {"name": "q", "type": "text", "value": ""},
            {"name": "Submit", "type": "submit", "value": "Search"},
        ],
    }]}

    targets = form_controls.build_form_targets(data, ("submit",))

    assert targets == [{
        "url": "https://lab.test/search/?locale=en&Submit=Search",
        "param": "q", "value": "", "method": "GET",
    }]


def test_multiple_named_submit_buttons_produce_separate_get_targets():
    form = {"url": "https://lab.test/action", "method": "GET", "inputs": [
        {"name": "item", "type": "text", "value": "1"},
        {"name": "action", "type": "submit", "value": "preview"},
        {"name": "action", "type": "submit", "value": "delete"},
    ]}

    assert form_controls.build_form_targets({"forms": [form]}, ("submit",)) == [
        {"url": "https://lab.test/action?action=preview", "param": "item", "value": "1", "method": "GET"},
        {"url": "https://lab.test/action?action=delete", "param": "item", "value": "1", "method": "GET"},
    ]


def test_unnamed_submit_and_non_get_forms_do_not_change_action_url():
    unnamed = {"url": "https://lab.test/search", "method": "GET", "inputs": [
        {"name": "q", "type": "text", "value": "abc"},
        {"name": "", "type": "submit", "value": "Search"},
    ]}
    post = {"url": "https://lab.test/save", "method": "POST", "inputs": [
        {"name": "q", "type": "text", "value": "abc"},
        {"name": "Submit", "type": "submit", "value": "Save"},
    ]}

    assert form_controls.build_form_targets({"forms": [unnamed, post]}, ("submit",)) == [
        {"url": "https://lab.test/search", "param": "q", "value": "abc", "method": "GET"},
        {"url": "https://lab.test/save", "param": "q", "value": "abc", "method": "POST",
         "form_data": {"Submit": "Save"}},
    ]


def test_post_targets_preserve_sibling_and_selected_submit_controls():
    form = {"url": "https://lab.test/guestbook", "method": "POST", "inputs": [
        {"name": "txtName", "type": "text", "value": ""},
        {"name": "mtxMessage", "type": "textarea", "value": ""},
        {"name": "btnSign", "type": "submit", "value": "Sign"},
        {"name": "btnClear", "type": "submit", "value": "Clear"},
    ]}
    targets = form_controls.build_form_targets({"forms": [form]}, ("submit",))
    message_targets = [target for target in targets if target["param"] == "mtxMessage"]
    assert [target["form_data"] for target in message_targets] == [
        {"txtName": "", "btnSign": "Sign"},
        {"txtName": "", "btnClear": "Clear"},
    ]
