import streamlit as st
import numpy as np
import pandas as pd
import re
import ipaddress
import urllib.parse
import joblib
import pickle
from tensorflow import keras

# ================= LOAD MODEL & OBJECTS =================

@st.cache_resource
def load_model():
    model = keras.models.load_model("phishing_model.h5")
    scaler = joblib.load("scaler.pkl")
    with open("feature_names.pkl", "rb") as f:
        feature_names = pickle.load(f)
    return model, scaler, feature_names

model, scaler, TRAIN_FEATURE_NAMES = load_model()

# ================= FEATURE EXTRACTOR (YOUR SAME LOGIC) =================

def extract_dataset_features(url):
    if not re.match(r"^https?", url):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    full_url = url

    NumDots = full_url.count('.')
    SubdomainLevel = max(0, domain.count('.') - 1)
    PathLevel = path.count('/')
    UrlLength = len(full_url)
    NumDash = full_url.count('-')
    NumDashInHostname = domain.count('-')
    AtSymbol = 1 if "@" in full_url else 0
    TildeSymbol = 1 if "~" in full_url else 0
    NumUnderscore = full_url.count('_')
    NumPercent = full_url.count('%')
    NumQueryComponents = len(query.split('&')) if query else 0
    NumAmpersand = full_url.count('&')
    NumHash = full_url.count('#')
    NumNumericChars = sum(c.isdigit() for c in full_url)

    NoHttps = 1 if parsed.scheme != "https" else 0
    RandomString = 1 if re.search(r"[a-z0-9]{10,}", domain) else 0

    try:
        ipaddress.ip_address(domain)
        IpAddress = 1
    except:
        IpAddress = 0

    DomainInSubdomains = 1 if domain.split('.')[0] in full_url else 0
    DomainInPaths = 1 if domain.split('.')[0] in path else 0
    HttpsInHostname = 1 if "https" in domain else 0

    HostnameLength = len(domain)
    PathLength = len(path)
    QueryLength = len(query)
    DoubleSlashInPath = 1 if "//" in path else 0

    sensitive_words = ["login","secure","bank","verify","account","update"]
    NumSensitiveWords = sum(1 for w in sensitive_words if w in full_url.lower())

    common_brands = ["google","facebook","amazon","paypal","microsoft","apple","netflix"]
    EmbeddedBrandName = 1 if any(b in domain for b in common_brands) else 0

    PctExtHyperlinks = 0.0
    PctExtResourceUrls = 0.0
    ExtFavicon = 1 if "favicon" in full_url.lower() else 0
    InsecureForms = 1 if parsed.scheme == "http" else 0
    RelativeFormAction = 0
    ExtFormAction = 0
    AbnormalFormAction = 0
    PctNullSelfRedirectHyperlinks = 0.0
    FrequentDomainNameMismatch = 0
    FakeLinkInStatusBar = 0
    RightClickDisabled = 0
    PopUpWindow = 0
    SubmitInfoToEmail = 0
    IframeOrFrame = 1 if "iframe" in full_url.lower() else 0
    MissingTitle = 0
    ImagesOnlyInForm = 0

    SubdomainLevelRT = 1 if SubdomainLevel > 1 else 0
    UrlLengthRT = 1 if UrlLength > 75 else 0
    PctExtResourceUrlsRT = 1 if PctExtResourceUrls > 0.5 else 0
    AbnormalExtFormActionR = AbnormalFormAction
    ExtMetaScriptLinkRT = 0
    PctExtNullSelfRedirectHyperlinksRT = 0

    features = np.array([
        NumDots, SubdomainLevel, PathLevel, UrlLength, NumDash,
        NumDashInHostname, AtSymbol, TildeSymbol, NumUnderscore, NumPercent,
        NumQueryComponents, NumAmpersand, NumHash, NumNumericChars, NoHttps,
        RandomString, IpAddress, DomainInSubdomains, DomainInPaths,
        HttpsInHostname, HostnameLength, PathLength, QueryLength,
        DoubleSlashInPath, NumSensitiveWords, EmbeddedBrandName,
        PctExtHyperlinks, PctExtResourceUrls, ExtFavicon, InsecureForms,
        RelativeFormAction, ExtFormAction, AbnormalFormAction,
        PctNullSelfRedirectHyperlinks, FrequentDomainNameMismatch,
        FakeLinkInStatusBar, RightClickDisabled, PopUpWindow,
        SubmitInfoToEmail, IframeOrFrame, MissingTitle, ImagesOnlyInForm,
        SubdomainLevelRT, UrlLengthRT, PctExtResourceUrlsRT,
        AbnormalExtFormActionR, ExtMetaScriptLinkRT,
        PctExtNullSelfRedirectHyperlinksRT
    ], dtype=np.float32)

    return features

# ================= STREAMLIT UI =================

st.set_page_config(page_title="Phishing URL Detector", layout="centered")

st.title("🔐 Phishing URL Detection System")
st.write("Enter a URL below to check whether it is **Phishing or Legitimate**.")

url_input = st.text_input("Enter URL:", "")

THRESHOLD = 0.35

if st.button("Check URL"):
    if url_input.strip() == "":
        st.warning("Please enter a valid URL.")
    else:
        with st.spinner("Analyzing URL..."):
            raw_features = extract_dataset_features(url_input)
            df_live = pd.DataFrame([raw_features], columns=TRAIN_FEATURE_NAMES)
            features_scaled = scaler.transform(df_live)

            prob = model.predict(features_scaled, verbose=0)[0][0]

        st.write("---")
        if prob > THRESHOLD:
            st.error(f"🚨 PHISHING DETECTED — Confidence: {prob*100:.2f}%")
            st.write("⚠️ Do NOT click this link.")
        else:
            st.success(f"✅ LEGITIMATE — Confidence: {(1-prob)*100:.2f}%")
            st.write("👍 Safe to proceed.")
