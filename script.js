const API_BASE = (window.SCAMSHIELD_API_BASE || (window.location.port === "4173" ? "http://127.0.0.1:8000" : "")).replace(/\/$/, "");
const form = document.querySelector("#analysis-form");
const messageInput = document.querySelector("#message-input");
const urlInput = document.querySelector("#url-input");
const analyzeButton = document.querySelector("#analyze-button");
const formError = document.querySelector("#form-error");
const resultsPanel = document.querySelector("#results-panel");
const emptyState = document.querySelector("#empty-state");
const resultsContent = document.querySelector("#results-content");
const followUpForm = document.querySelector("#follow-up-form");
const followUpInput = document.querySelector("#follow-up-input");
const followUpMessages = document.querySelector("#follow-up-messages");
const analysisStatus = document.querySelector("#analysis-status");
const demoStatus = document.querySelector("#demo-status");
let latestInvestigationToken = null;
let followUpAvailable = false;

const demoMessage = "Your bank account will be blocked today unless you verify it immediately at https://example.invalid/verify. Reply with your OTP.";
const demoUrl = "https://example.invalid/verify";

function setLoading(loading) {
  analyzeButton.disabled = loading;
  analyzeButton.classList.toggle("is-loading", loading);
  analyzeButton.setAttribute("aria-busy", String(loading));
  analyzeButton.setAttribute("aria-label", loading ? "Analyzing message" : "Analyze message");
}

function setAnalysisStatus(message, state = "") {
  analysisStatus.textContent = message;
  analysisStatus.hidden = !message;
  analysisStatus.className = `analysis-status${state ? ` is-${state}` : ""}`;
}

function showError(message) {
  formError.textContent = message;
  formError.hidden = false;
}

function clearError() {
  formError.hidden = true;
  formError.textContent = "";
}

function textElement(tagName, className, text) {
  const element = document.createElement(tagName);
  if (className) element.className = className;
  element.textContent = String(text);
  return element;
}

function replaceTextList(container, values, tagName = "li") {
  container.replaceChildren(...values.map((value) => textElement(tagName, "", value)));
}

function setFollowUpAvailability(available, message) {
  followUpAvailable = available;
  const button = followUpForm.querySelector("button");
  followUpInput.disabled = !available;
  button.disabled = !available;
  followUpInput.placeholder = available ? "Ask what to do next…" : "Follow-up unavailable";
  followUpMessages.replaceChildren(
    textElement("p", available ? "follow-up-placeholder" : "follow-up-unavailable", message)
  );
}

function statusLabel(status) {
  return status === "suspicious" ? "Suspicious findings" : "Inconclusive";
}

function iconFor(indicator) {
  return {
    upfront_payment: "₿",
    credential_request: "⌁",
    urgency_threat: "!",
    prize_reward: "✦",
    suspicious_job_offer: "↗",
    impersonation: "◉",
    url_for_investigation: "⌘"
  }[indicator] || "?";
}

function verificationSummary(urlCheck) {
  if (!urlCheck) return "No external URL verification was requested.";
  const messages = {
    malicious: "The configured reputation provider reported a threat match. Do not open the URL.",
    no_threat_found: "A provider found no matching threat at lookup time. This does not prove the URL is safe.",
    unknown: "No reputation provider is configured. The URL has not been independently verified.",
    lookup_failed: "The reputation provider could not complete the lookup. Treat the result as unknown.",
    provider_error: "The reputation provider could not complete the lookup. Treat the result as unknown."
  };
  return messages[urlCheck.status] || "The URL verification status is unavailable.";
}

function renderResults(result) {
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const status = result.status === "suspicious" ? "suspicious" : "inconclusive";
  const statusElement = document.querySelector("#result-status");
  statusElement.textContent = statusLabel(status);
  statusElement.className = `status-badge ${status}`;
  document.querySelector("#result-title").textContent = status === "suspicious" ? "Pause before acting" : "No clear conclusion";
  const assessment = result.explanation?.assessment;
  document.querySelector("#result-summary").textContent = (typeof assessment === "string" && assessment.trim()) ? assessment : (status === "suspicious"
    ? "The available checks found warning signs worth verifying independently."
    : "The available checks do not provide enough evidence for a strong conclusion.");
  document.querySelector("#result-count").textContent = `${findings.length} signal${findings.length === 1 ? "" : "s"} observed`;
  document.querySelector("#finding-count").textContent = findings.length;
  const evidenceList = document.querySelector("#evidence-list");
  evidenceList.replaceChildren();
  if (findings.length) {
    for (const finding of findings) {
      const indicator = typeof finding.indicator_type === "string" ? finding.indicator_type : "warning_indicator";
      const card = document.createElement("article");
      card.className = "evidence-card";
      const heading = document.createElement("div");
      heading.className = "evidence-card-top";
      const icon = textElement("span", "evidence-icon", iconFor(indicator));
      icon.setAttribute("aria-hidden", "true");
      heading.append(icon, textElement("strong", "", indicator.replaceAll("_", " ")));
      if (typeof finding.severity === "string" && finding.severity.trim()) {
        heading.append(textElement("span", "severity", finding.severity));
      }
      card.append(heading);
      if (finding.supporting_text) card.append(textElement("blockquote", "", `“${finding.supporting_text}”`));
      if (typeof finding.explanation === "string" && finding.explanation.trim()) {
        card.append(textElement("p", "", finding.explanation));
      }
      if (finding.recommended_verification) {
        card.append(textElement("p", "verify-line", finding.recommended_verification));
      }
      evidenceList.append(card);
    }
  } else {
    evidenceList.append(textElement("p", "no-findings", "No clear warning signal was detected by these preliminary checks."));
  }
  document.querySelector("#verification-text").textContent = verificationSummary(result.url_check);
  const providedSteps = Array.isArray(result.explanation?.recommended_next_steps) && result.explanation.recommended_next_steps.length
    ? result.explanation.recommended_next_steps
    : (Array.isArray(result.recommendations) ? result.recommendations : []);
  const usableSteps = providedSteps.filter((step) => typeof step === "string" && step.trim());
  const nextSteps = document.querySelector("#next-steps-list");
  if (usableSteps.length) {
    replaceTextList(nextSteps, usableSteps);
  } else {
    nextSteps.replaceChildren(textElement("li", "no-next-steps", "No additional next steps were returned for this result."));
  }
  const limitations = Array.isArray(result.limitations)
    ? result.limitations.filter((item) => typeof item === "string" && item.trim())
    : ["This is a preliminary analysis and cannot guarantee fraud detection."];
  const uncertainty = result.explanation?.uncertainty_explanation;
  const uncertaintyElement = document.querySelector("#result-uncertainty");
  uncertaintyElement.hidden = typeof uncertainty !== "string" || !uncertainty.trim();
  uncertaintyElement.textContent = uncertaintyElement.hidden ? "" : `Uncertainty: ${uncertainty}`;
  replaceTextList(document.querySelector("#limitations"), limitations, "p");
  emptyState.hidden = true;
  resultsContent.hidden = false;
  const bedrockUnavailable = limitations.some((item) => item.startsWith("Amazon Bedrock is not configured;"));
  latestInvestigationToken = result._follow_up_token || null;
  setFollowUpAvailability(
    !bedrockUnavailable,
    bedrockUnavailable
      ? "Follow-up explanations require Amazon Bedrock, which is not configured."
      : "Your follow-up conversation will appear here after an analysis."
  );
}

async function analyze(event) {
  event.preventDefault();
  clearError();
  demoStatus.hidden = true;
  const message = messageInput.value.trim();
  const url = urlInput.value.trim();
  if (!message) {
    setAnalysisStatus("");
    showError("Paste the message you want to investigate first.");
    messageInput.focus();
    return;
  }
  resultsContent.hidden = true;
  emptyState.hidden = false;
  latestInvestigationToken = null;
  setFollowUpAvailability(false, "Follow-up is available after an analysis when Bedrock is configured.");
  setAnalysisStatus("Analyzing message and any supplied link…", "loading");
  setLoading(true);
  try {
    const response = await fetch(`${API_BASE}/api/investigate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, url: url || null })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok || !payload?.ok || !payload.result || typeof payload.result !== "object" || Array.isArray(payload.result)) {
      const apiMessage = typeof payload?.error?.message === "string" ? payload.error.message : null;
      throw new Error(apiMessage || "The analysis service could not complete the request.");
    }
    renderResults(payload.result);
    setAnalysisStatus("Analysis complete. Review the assessment, evidence, and next steps.", "success");
    resultsPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    setAnalysisStatus("");
    showError(error instanceof TypeError
      ? "Could not reach ScamShield. Check that the FastAPI backend is running, then retry."
      : (error.message || "The analysis could not be completed. Please retry."));
  } finally {
    setLoading(false);
  }
}

async function askFollowUp(event) {
  event.preventDefault();
  const question = followUpInput.value.trim();
  if (!question || !latestInvestigationToken || followUpInput.disabled) return;
  const button = followUpForm.querySelector("button");
  followUpInput.disabled = true;
  button.disabled = true;
  followUpForm.setAttribute("aria-busy", "true");
  followUpMessages.append(textElement("p", "follow-up-user", question));
  const loadingMessage = textElement("p", "follow-up-loading", "Checking the current findings…");
  followUpMessages.append(loadingMessage);
  try {
    const response = await fetch(`${API_BASE}/api/follow-up`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, investigation_token: latestInvestigationToken })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok || !payload?.ok || typeof payload.result?.answer !== "string") {
      const apiMessage = typeof payload?.error?.message === "string" ? payload.error.message : null;
      throw new Error(apiMessage || "Follow-up guidance is unavailable.");
    }
    loadingMessage.remove();
    followUpMessages.append(textElement("p", "follow-up-assistant", payload.result.answer));
    if (Array.isArray(payload.result.next_steps) && payload.result.next_steps.length) {
      const steps = document.createElement("ul");
      steps.className = "follow-up-next-steps";
      for (const step of payload.result.next_steps) {
        if (typeof step === "string" && step.trim()) steps.append(textElement("li", "", step));
      }
      if (steps.childElementCount) followUpMessages.append(steps);
    }
    if (typeof payload.result.uncertainty === "string" && payload.result.uncertainty.trim()) {
      followUpMessages.append(textElement("p", "follow-up-uncertainty", `What remains uncertain: ${payload.result.uncertainty}`));
    }
    followUpInput.value = "";
  } catch (error) {
    loadingMessage.remove();
    appendFollowUpError(error instanceof TypeError
      ? "Could not reach the follow-up service. Check that the backend is running, then retry."
      : (error.message || "Follow-up guidance is unavailable."));
  } finally {
    followUpForm.setAttribute("aria-busy", "false");
    followUpInput.disabled = !followUpAvailable;
    button.disabled = !followUpAvailable;
  }
}

function appendFollowUpError(message) {
  followUpMessages.append(textElement("p", "follow-up-error", message));
}

messageInput.addEventListener("input", () => {
  document.querySelector("#message-count").textContent = `${messageInput.value.length.toLocaleString()} / 10,000`;
});
form.addEventListener("submit", analyze);
followUpForm.addEventListener("submit", askFollowUp);
document.querySelector("#load-demo").addEventListener("click", () => {
  messageInput.value = demoMessage;
  urlInput.value = demoUrl;
  messageInput.dispatchEvent(new Event("input"));
  messageInput.focus();
  clearError();
  setAnalysisStatus("");
  demoStatus.textContent = "Synthetic example loaded. Review it, then select Analyze message.";
  demoStatus.hidden = false;
});
document.querySelector("#reset-button").addEventListener("click", () => {
  latestInvestigationToken = null;
  resultsContent.hidden = true;
  emptyState.hidden = false;
  setFollowUpAvailability(false, "Your follow-up conversation will appear here after an analysis.");
  window.scrollTo({ top: document.querySelector("#investigate").offsetTop - 20, behavior: "smooth" });
});
document.querySelector("#mobile-menu").addEventListener("click", (event) => {
  const nav = document.querySelector(".header-nav");
  const open = nav.classList.toggle("is-open");
  event.currentTarget.setAttribute("aria-expanded", String(open));
});
