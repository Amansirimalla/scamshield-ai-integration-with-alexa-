const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

class FakeElement {
  constructor(tagName = "div") {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.listeners = {};
    this.attributes = {};
    this.className = "";
    this.value = "";
    this.disabled = false;
    this.hidden = false;
    this.placeholder = "";
    this.textContent = "";
    this.classList = {
      toggle: (name, enabled) => {
        const names = new Set(this.className.split(/\s+/).filter(Boolean));
        if (enabled) names.add(name);
        else names.delete(name);
        this.className = [...names].join(" ");
      }
    };
  }

  set innerHTML(_value) {
    throw new Error("Unsafe HTML insertion is forbidden in this test.");
  }

  addEventListener(name, handler) {
    this.listeners[name] = handler;
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }

  append(...elements) {
    for (const element of elements) {
      if (element.parentElement) element.remove();
      element.parentElement = this;
      this.children.push(element);
    }
  }

  replaceChildren(...elements) {
    this.children = [];
    this.append(...elements);
  }

  remove() {
    if (!this.parentElement) return;
    this.parentElement.children = this.parentElement.children.filter((item) => item !== this);
    this.parentElement = null;
  }

  focus() {
    this.ownerDocument.activeElement = this;
  }

  scrollIntoView() {}

  querySelector(selector) {
    if (selector === "button") return this.button;
    return null;
  }

  get childElementCount() {
    return this.children.length;
  }
}

const script = fs.readFileSync(path.join(__dirname, "..", "script.js"), "utf8");

function setup(fetchImpl) {
  const elements = new Map();
  const created = [];
  const document = {
    activeElement: null,
    querySelector(selector) {
      if (!elements.has(selector)) {
        const element = new FakeElement(selector === "#analysis-form" || selector === "#follow-up-form" ? "form" : "div");
        element.ownerDocument = document;
        elements.set(selector, element);
      }
      return elements.get(selector);
    },
    createElement(tagName) {
      const element = new FakeElement(tagName);
      element.ownerDocument = document;
      created.push(element);
      return element;
    }
  };
  const followUpForm = document.querySelector("#follow-up-form");
  followUpForm.button = new FakeElement("button");
  const context = {
    document,
    window: { SCAMSHIELD_API_BASE: "http://test.local", location: { port: "4173" }, scrollTo() {} },
    fetch: fetchImpl,
    TypeError,
    Event: class Event { constructor(type) { this.type = type; } }
  };
  vm.runInNewContext(script, context, { filename: "script.js" });
  return { document, elements, created };
}

function apiResponse(payload, { ok = true, status = 200 } = {}) {
  return { ok, status, json: async () => payload };
}

function textOf(element) {
  return [element.textContent, ...element.children.map(textOf)].filter(Boolean).join(" ");
}

async function submitAnalysis(ui, message) {
  ui.elements.get("#message-input").value = message;
  await ui.elements.get("#analysis-form").listeners.submit({ preventDefault() {} });
}

const suspiciousApiResult = {
  ok: true,
  result: {
    status: "suspicious",
    findings: [
      { indicator_type: "upfront_payment", supporting_text: "Pay a registration fee", explanation: "Requests upfront payment.", severity: "high", recommended_verification: "Verify through official channels." },
      { indicator_type: "urgency_threat", supporting_text: "today or your account will be blocked", explanation: "Uses urgency.", severity: "medium", recommended_verification: "Contact the organization directly." }
    ],
    url_check: null,
    recommendations: ["Verify through official channels."],
    limitations: ["These are preliminary indicators, not proof of fraud."],
    explanation: null,
    _follow_up_token: "synthetic-signed-token"
  }
};

test("renders multiple warning indicators from the real API response envelope", async () => {
  const ui = setup(async () => apiResponse(suspiciousApiResult));
  await submitAnalysis(ui, "Synthetic payment and urgency message.");

  assert.equal(ui.elements.get("#result-status").textContent, "Suspicious findings");
  assert.equal(ui.elements.get("#finding-count").textContent, 2);
  assert.match(textOf(ui.elements.get("#evidence-list")), /upfront payment/);
  assert.match(textOf(ui.elements.get("#evidence-list")), /urgency threat/);
  assert.match(textOf(ui.elements.get("#next-steps-list")), /Verify through official channels/);
});

test("shows no findings as inconclusive and does not promise safety", async () => {
  const result = structuredClone(suspiciousApiResult);
  result.result.status = "inconclusive";
  result.result.findings = [];
  result.result.limitations = ["No finding does not prove the message is safe."];
  const ui = setup(async () => apiResponse(result));
  await submitAnalysis(ui, "Synthetic ordinary appointment reminder.");

  assert.equal(ui.elements.get("#result-status").textContent, "Inconclusive");
  assert.match(textOf(ui.elements.get("#evidence-list")), /No clear warning signal/);
  assert.doesNotMatch(textOf(ui.elements.get("#results-content")), /This message is safe/i);
  assert.match(textOf(ui.elements.get("#limitations")), /does not prove the message is safe/);
});

test("rejects an unexpected API result structure with visible feedback", async () => {
  const ui = setup(async () => apiResponse({ ok: true, result: [] }));
  await submitAnalysis(ui, "Synthetic message.");

  assert.equal(ui.elements.get("#form-error").hidden, false);
  assert.match(ui.elements.get("#form-error").textContent, /analysis service could not complete/i);
});

test("shows backend HTTP and network failures", async (t) => {
  await t.test("HTTP error", async () => {
    const ui = setup(async () => apiResponse({ detail: "invalid" }, { ok: false, status: 422 }));
    await submitAnalysis(ui, "Synthetic message.");
    assert.equal(ui.elements.get("#form-error").hidden, false);
  });

  await t.test("unreachable backend", async () => {
    const ui = setup(async () => { throw new TypeError("fetch failed"); });
    await submitAnalysis(ui, "Synthetic message.");
    assert.match(ui.elements.get("#form-error").textContent, /Could not reach ScamShield/);
  });
});

test("communicates failed or inconclusive URL reputation without calling it safe", async (t) => {
  for (const status of ["unknown", "lookup_failed", "provider_error"]) {
    await t.test(status, async () => {
      const result = structuredClone(suspiciousApiResult);
      result.result.url_check = { status, limitations: ["Synthetic lookup state."] };
      const ui = setup(async () => apiResponse(result));
      await submitAnalysis(ui, "Synthetic message with a link.");

      const text = ui.elements.get("#verification-text").textContent;
      assert.match(text, /provider is configured|not independently verified|could not complete/i);
      assert.doesNotMatch(text, /safe/i);
    });
  }
});

test("disables follow-up controls when API reports Bedrock is unconfigured", async () => {
  const result = structuredClone(suspiciousApiResult);
  result.result.limitations.push("Amazon Bedrock is not configured; this result uses MCP tool findings only.");
  const ui = setup(async () => apiResponse(result));
  await submitAnalysis(ui, "Synthetic message.");

  assert.equal(ui.elements.get("#follow-up-input").disabled, true);
  assert.equal(ui.elements.get("#follow-up-form").button.disabled, true);
  assert.match(textOf(ui.elements.get("#follow-up-messages")), /Bedrock.*not configured/i);
});

test("handles empty input locally and invalid API input with feedback", async (t) => {
  await t.test("empty input is rejected before fetch", async () => {
    let calls = 0;
    const ui = setup(async () => { calls += 1; return apiResponse({}); });
    await submitAnalysis(ui, "   ");
    assert.equal(calls, 0);
    assert.equal(ui.document.activeElement, ui.elements.get("#message-input"));
    assert.match(ui.elements.get("#form-error").textContent, /Paste the message/);
  });

  await t.test("API validation response is shown", async () => {
    const ui = setup(async () => apiResponse({ ok: false, error: { code: "invalid_input", message: "Message is invalid." } }));
    await submitAnalysis(ui, "Synthetic message.");
    assert.match(ui.elements.get("#form-error").textContent, /Message is invalid/);
  });
});

test("renders HTML-like user and API text as text nodes", async () => {
  const hostile = '<img src=x onerror="alert(1)">';
  const result = structuredClone(suspiciousApiResult);
  result.result.findings[0].supporting_text = hostile;
  result.result.findings[0].explanation = hostile;
  const fetchImpl = async (_url, options) => {
    if (options.body.includes("investigation_token")) {
      return apiResponse({ ok: true, result: { answer: hostile, next_steps: [hostile], uncertainty: hostile } });
    }
    return apiResponse(result);
  };
  const ui = setup(fetchImpl);
  await submitAnalysis(ui, "Synthetic message.");
  const followInput = ui.elements.get("#follow-up-input");
  followInput.value = hostile;
  await ui.elements.get("#follow-up-form").listeners.submit({ preventDefault() {} });

  assert.equal(ui.created.some((element) => element.tagName === "IMG"), false);
  assert.equal(ui.created.filter((element) => element.textContent === hostile).length >= 3, true);
  assert.match(textOf(ui.elements.get("#follow-up-messages")), /<img src=x onerror=/);
});
