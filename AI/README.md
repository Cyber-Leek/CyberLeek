# AI Investigation Layer

This folder contains the AI-based investigation and explanation components of the
Explainable Network IDS.

## Purpose

The AI layer is responsible for:

- Explaining why a network flow was classified as suspicious
- Summarizing important evidence
- Providing analyst-friendly security explanations
- Using the Knowledge Base to add context to detected threats

## Current Architecture

Random Forest
    ↓
Prediction
    ↓
Important Features
    ↓
AI Investigation
    ↓
Human-readable Explanation

The local ML model performs the primary detection. An external LLM/API can
optionally be used later for advanced explanations and investigation summaries.