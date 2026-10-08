# The Overloaded Phishing Inbox

The Overloaded Phishing Inbox is a phishing email triage application developed by Code Mavericks for Microsoft Innovate 2026.

## What the project does

The application accepts an email and analyzes headers, URLs/domains, and email text. These results are combined into a risk score from 0 to 100.

### Main features
- Header analysis: SPF, DKIM, DMARC, sender mismatches
- URL/domain analysis: IP URLs, suspicious TLDs, punycode, look-alike domains, non-HTTPS URLs
- NLP analysis using a TF-IDF + Logistic Regression pipeline
- Explainable triage dashboard with risk score and evidence

## Project structure

    app.py
    train_model.py
    requirements.txt
    .env.example
    .gitignore
    README.md
    data/
    models/
    static/
    templates/

## Requirements

Python 3.10+ and pip are recommended.

## Installation

    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt

Copy `.env.example` to `.env` for optional configuration.

## Running

    python app.py

Then open the Flask local URL in your browser.

## Training the text model

The training script expects `data/CEAS_08.csv` and writes the trained pipeline to `models/nlp_pipeline.joblib`.

## Team

Code Mavericks

Team members:
- Aman Kumar
- Jai Gupta
- Krish Astwal
- Arpit Tyagi

This repository is a duplicate/copy of the project source repository for Jai Gupta's project portfolio and development work.
