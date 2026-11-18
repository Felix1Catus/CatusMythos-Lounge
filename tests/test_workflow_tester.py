"""Regression tests for webapp-exploit-hunter's workflow_tester.py.

This script is new in this pass -- it closes a structural gap in the
pipeline: every other tester probes one endpoint/parameter at a time, but
a human pentester maps the actual multi-step business flow (checkout,
signup, onboarding) and attacks the SEQUENCE: can a later step be reached
without completing the earlier ones. workflow_tester.py discovers candidate
workflows from crawl data (a form-chain graph built from the crawler's own
`found_on`/`url` fields, and a path-prefix/keyword grouping as a second,
independent signal) and tests step-skip access, read-only (GET only, no
form submission ever).

Locks:
- the step-ordering heuristic bug caught and fixed during development:
  keyword rank (start/mid/review/confirm) must be the PRIMARY sort key, an
  explicit step number only a tiebreaker WITHIN the same rank -- a
  numberless "start" must sort before a numbered "step2", not after it;
- the form-chain graph only follows truly linear (unbranching) paths and
  stops at branch points / cycles;
- classify_step_access's enforced/candidate/inconclusive boundaries (a bare
  200 is only ever a CANDIDATE, never a confirmed finding, matching the
  rest of this repo's "don't overclaim from a bare response" discipline);
- test_step_skip never probes step 0 of a workflow and never sends
  anything but GET.
"""
import importlib.util
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "skills" / "webapp-exploit-hunter" / "scripts"


def load_script(name, filename):
    path = SCRIPTS / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    original_common = sys.modules.pop("_common", None)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(path.parent))
        sys.modules.pop("_common", None)
        if original_common is not None:
            sys.modules["_common"] = original_common
    return module


wf = load_script("weh_workflow_tester", "workflow_tester.py")


@contextmanager
def patched(module, attr, value):
    sentinel = object()
    original = getattr(module, attr, sentinel)
    setattr(module, attr, value)
    try:
        yield
    finally:
        if original is sentinel:
            delattr(module, attr)
        else:
            setattr(module, attr, original)


# ---------------------------------------------------------------------------
# path-prefix step ordering
# ---------------------------------------------------------------------------
class TestStepRank(unittest.TestCase):
    def test_start_keyword(self):
        self.assertEqual(wf._step_rank("/start")[1], 0)

    def test_terminal_keyword(self):
        self.assertEqual(wf._step_rank("/confirm")[1], 4)

    def test_explicit_number_extracted(self):
        self.assertEqual(wf._step_rank("/step3")[0], 3)

    def test_no_number_in_plain_word(self):
        self.assertIsNone(wf._step_rank("/review")[0])


class TestGroupByStepPrefix(unittest.TestCase):
    def test_orders_start_before_numbered_before_terminal(self):
        # Regression: keyword rank (start=0) must dominate an explicit
        # number (step2=2) -- a prior version of the sort key put any
        # numbered segment ahead of any unnumbered one and broke this.
        paths = ["/checkout/start", "/checkout/step2", "/checkout/review", "/checkout/confirm"]
        groups = wf.group_endpoints_by_step_prefix(paths)
        self.assertEqual(groups["/checkout"],
                         ["/checkout/start", "/checkout/step2", "/checkout/review", "/checkout/confirm"])

    def test_numbered_steps_ordered_among_themselves(self):
        paths = ["/signup/step1", "/signup/step3", "/signup/step2"]
        groups = wf.group_endpoints_by_step_prefix(paths)
        self.assertEqual(groups["/signup"], ["/signup/step1", "/signup/step2", "/signup/step3"])

    def test_single_match_is_not_a_workflow(self):
        # One matching path alone isn't a multi-step flow worth reporting.
        groups = wf.group_endpoints_by_step_prefix(["/checkout/start", "/about", "/contact"])
        self.assertEqual(groups, {})

    def test_non_workflow_paths_ignored(self):
        groups = wf.group_endpoints_by_step_prefix(["/about", "/contact", "/blog/post-1"])
        self.assertEqual(groups, {})

    def test_unrecognized_prefix_not_grouped_with_recognized_one(self):
        paths = ["/checkout/start", "/checkout/step2", "/blog/post-1", "/blog/post-2"]
        groups = wf.group_endpoints_by_step_prefix(paths)
        self.assertIn("/checkout", groups)
        self.assertNotIn("/blog", groups)  # "blog" isn't a workflow keyword


# ---------------------------------------------------------------------------
# form-chain graph discovery
# ---------------------------------------------------------------------------
class TestFormChainGraph(unittest.TestCase):
    def test_builds_edges_from_found_on_and_url(self):
        forms = [{"found_on": "https://t.test/a", "url": "https://t.test/b"}]
        self.assertEqual(wf.build_form_chain_graph(forms), {"https://t.test/a": {"https://t.test/b"}})

    def test_self_loop_ignored(self):
        forms = [{"found_on": "https://t.test/a", "url": "https://t.test/a"}]
        self.assertEqual(wf.build_form_chain_graph(forms), {})

    def test_missing_fields_ignored(self):
        forms = [{"found_on": "https://t.test/a"}, {"url": "https://t.test/b"}, {}]
        self.assertEqual(wf.build_form_chain_graph(forms), {})


class TestLinearChains(unittest.TestCase):
    def test_simple_linear_chain(self):
        graph = {"a": {"b"}, "b": {"c"}}
        self.assertEqual(wf.find_linear_chains(graph), [["a", "b", "c"]])

    def test_branch_point_stops_the_chain(self):
        # a -> {b, c} is a branch -- the chain from 'a' must stop AT 'a'
        # (length 1, dropped by min_length) rather than picking one branch.
        graph = {"a": {"b", "c"}}
        self.assertEqual(wf.find_linear_chains(graph), [])

    def test_cycle_does_not_infinite_loop(self):
        graph = {"a": {"b"}, "b": {"a"}}
        chains = wf.find_linear_chains(graph)
        # Must terminate and produce at most a short chain, never hang.
        for chain in chains:
            self.assertLessEqual(len(chain), 2)

    def test_two_node_chain_meets_default_min_length(self):
        # A single edge IS already a minimal 2-step workflow -- min_length=2
        # (the default) keeps it; only a 1-node "chain" (no edges at all,
        # which find_linear_chains never produces as a start node) would
        # be dropped.
        graph = {"a": {"b"}}
        self.assertEqual(wf.find_linear_chains(graph, min_length=2), [["a", "b"]])

    def test_min_length_three_drops_a_two_node_chain(self):
        graph = {"a": {"b"}}
        self.assertEqual(wf.find_linear_chains(graph, min_length=3), [])

    def test_start_node_has_no_incoming_edge(self):
        # b is both a target (from a) and a source (to c); the chain must
        # start at 'a' (no incoming edge), not list 'b' as its own start.
        graph = {"a": {"b"}, "b": {"c"}}
        chains = wf.find_linear_chains(graph)
        self.assertEqual(chains[0][0], "a")


class TestDiscoverWorkflows(unittest.TestCase):
    def test_browser_report_handoff_is_exact_origin_and_builds_form_edges(self):
        report = {"pages": [
            {"url": "https://t.test/checkout/start", "forms": [
                {"action": "https://t.test/checkout/review", "method": "POST"}]},
            {"url": "https://evil.test/checkout/confirm", "forms": []},
        ]}
        crawl = wf.browser_report_to_crawl(report, "https://t.test")
        self.assertEqual(len(crawl["forms"]), 1)
        self.assertEqual(crawl["forms"][0]["method"], "POST")
        self.assertEqual(len(crawl["endpoints"]), 1)

    def test_combines_both_signals_when_distinct(self):
        # form_chain finds a (step1, step2, step3) checkout flow; the
        # endpoints list separately contains an unrelated signup flow that
        # ONLY the path-prefix signal can discover (no form edges link it).
        crawl_data = {
            "forms": [
                {"found_on": "https://t.test/checkout/step1", "url": "https://t.test/checkout/step2"},
                {"found_on": "https://t.test/checkout/step2", "url": "https://t.test/checkout/step3"},
            ],
            "endpoints": [
                {"path": "/signup/start", "url": "https://t.test/signup/start"},
                {"path": "/signup/verify", "url": "https://t.test/signup/verify"},
            ],
        }
        workflows = wf.discover_workflows(crawl_data)
        sources = {w["source"] for w in workflows}
        self.assertEqual(sources, {"form_chain", "path_prefix"})

    def test_identical_chain_from_both_signals_is_deduplicated(self):
        # When both signals land on the EXACT same step sequence, it must
        # be reported once, not twice.
        crawl_data = {
            "forms": [
                {"found_on": "https://t.test/checkout/step1", "url": "https://t.test/checkout/step2"},
            ],
            "endpoints": [
                {"path": "/checkout/step1", "url": "https://t.test/checkout/step1"},
                {"path": "/checkout/step2", "url": "https://t.test/checkout/step2"},
            ],
        }
        workflows = wf.discover_workflows(crawl_data)
        step_lists = [tuple(w["steps"]) for w in workflows]
        self.assertEqual(len(step_lists), len(set(step_lists)))

    def test_empty_crawl_data_yields_no_workflows(self):
        self.assertEqual(wf.discover_workflows({}), [])


# ---------------------------------------------------------------------------
# step-skip classification + testing
# ---------------------------------------------------------------------------
_STEPS = ["https://t.test/checkout/step1", "https://t.test/checkout/step2", "https://t.test/checkout/step3"]


class TestClassifyStepAccess(unittest.TestCase):
    def test_redirect_to_earlier_step_is_enforced(self):
        headers = {"Location": "/checkout/step1"}
        self.assertEqual(wf.classify_step_access(302, "", headers, _STEPS, 1), "enforced")

    def test_redirect_to_login_is_enforced(self):
        headers = {"Location": "/login"}
        self.assertEqual(wf.classify_step_access(302, "", headers, _STEPS, 1), "enforced")

    def test_redirect_to_unrelated_page_is_inconclusive(self):
        headers = {"Location": "/promo-banner"}
        self.assertEqual(wf.classify_step_access(302, "", headers, _STEPS, 1), "inconclusive")

    def test_401_403_is_enforced(self):
        self.assertEqual(wf.classify_step_access(401, "", {}, _STEPS, 1), "enforced")
        self.assertEqual(wf.classify_step_access(403, "", {}, _STEPS, 1), "enforced")

    def test_enforcement_phrase_in_200_body_is_enforced(self):
        body = "Please complete step 1 first before continuing."
        self.assertEqual(wf.classify_step_access(200, body, {}, _STEPS, 1), "enforced")

    def test_session_expired_phrase_is_enforced(self):
        self.assertEqual(wf.classify_step_access(200, "Your session has expired.", {}, _STEPS, 1), "enforced")

    def test_ordinary_200_is_candidate_not_confirmed(self):
        # The core discipline: a bare 200 is a LEAD, never a confirmed finding.
        self.assertEqual(wf.classify_step_access(200, "<html>Shipping address form</html>", {}, _STEPS, 1),
                         "candidate")

    def test_404_is_inconclusive(self):
        self.assertEqual(wf.classify_step_access(404, "", {}, _STEPS, 1), "inconclusive")

    def test_transport_failure_is_inconclusive(self):
        self.assertEqual(wf.classify_step_access(0, "", {}, _STEPS, 1), "inconclusive")


class TestStepSkip(unittest.TestCase):
    def _workflow(self):
        return {"name": "checkout flow", "source": "form_chain", "steps": _STEPS}

    def test_never_probes_step_zero(self):
        calls = []

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            calls.append(url)
            return 403, {}, "forbidden"

        with patched(wf, "http_request", fake):
            wf.test_step_skip(self._workflow(), delay=0)
        self.assertNotIn(_STEPS[0], calls)
        self.assertEqual(len(calls), len(_STEPS) - 1)

    def test_candidate_finding_shape(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            if url == _STEPS[1]:
                return 200, {}, "ordinary shipping form content"
            return 403, {}, "forbidden"

        with patched(wf, "http_request", fake):
            findings = wf.test_step_skip(self._workflow(), delay=0)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["type"], "workflow_step_skip_candidate")
        self.assertEqual(finding["severity"], "INFO")
        self.assertFalse(finding["validated"])
        self.assertEqual(finding["step_index"], 1)
        self.assertEqual(finding["preceding_steps"], [_STEPS[0]])

    def test_fully_enforced_workflow_yields_no_findings(self):
        def fake(url, method="GET", data=None, headers=None, timeout=10):
            return 302, {"Location": "/checkout/step1"}, ""

        with patched(wf, "http_request", fake):
            findings = wf.test_step_skip(self._workflow(), delay=0)
        self.assertEqual(findings, [])

    def test_only_get_requests_are_ever_sent(self):
        methods_used = []

        def fake(url, method="GET", data=None, headers=None, timeout=10):
            methods_used.append(method)
            return 403, {}, "forbidden"

        with patched(wf, "http_request", fake):
            wf.test_step_skip(self._workflow(), delay=0)
        self.assertTrue(all(m == "GET" for m in methods_used))


if __name__ == "__main__":
    unittest.main()
