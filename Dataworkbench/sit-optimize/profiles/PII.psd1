@{
    # ---------------------------------------------------------------------
    # Analysis profile: Personally Identifiable Information (PII)
    # ---------------------------------------------------------------------
    # Demonstrates re-targeting the same SIT-tuning pipeline at a different
    # sensitive information domain. The JSON container keys are deliberately
    # IDENTICAL to the Credentials profile so the web delta tool, report
    # consolidation, and run snapshots all keep working unchanged. Only the
    # wording, entity types, and risk guidance change.
    #
    # Mapping of the stable container keys for this domain:
    #   validated_credentials -> validated PII findings (e.g. SSN, passport)
    #   credential_pairs      -> linked identity pairs (e.g. name + SSN)
    #   credential_summary    -> PII finding totals
    # ---------------------------------------------------------------------

    Name        = 'PII'
    Description  = 'Personally identifiable information: national IDs, passports, contact and identity data.'
    DlpPolicy   = '*'
    FindingNoun = 'PII finding'

    # Operator-reviewed priorities supplied to every analysis run.
    AnalysisFocus = @'
  The current exact scope contains All Full Names only. Distinguish real person-name records from signatures, public business contacts, templates, examples, repeated system identities, and uncorroborated named entities. Require workload and nearby identity-record context before treating names as a true-positive guardrail. Do not analyze other PII categories unless their SIT IDs are explicitly added.
'@

    # Exact SIT scope. Analysis fails closed when both allow-lists are empty.
    SensitiveInformationTypeIds   = @('50b8b56b-4ef8-44c2-a924-03374f5831ce')
    SensitiveInformationTypeNames = @('All Full Names')

    ExtractionInstruction = @'
You are a **Data Privacy and PII Protection Expert** assisting with SIT (Sensitive Information Type) tuning for DLP. Your expertise spans national identifiers (SSN, NINO, national ID), passport and driver license numbers, dates of birth, full names with identifiers, postal and email addresses, and phone numbers. Ignore previous classifications. Focus EXCLUSIVELY on:

1. **Noise/False Positive Identification** (PRIMARY FOCUS): Categorize indicators as noise or false signals:
   - Order numbers, invoice IDs, tracking numbers, and reference codes shaped like IDs
   - Sequential or templated test identities in sample/demo data
   - Numbers that match an SSN/ID format but lack a valid checksum or surrounding identity context
   - Phone-like or date-like strings in logs, version numbers, and timestamps
   - Public business contact details (support lines, published addresses)
   - Repeated identical identities across many messages (likely test data or templates)
2. **Root Cause Analysis**: For each noisy indicator, identify why it triggers and the best suppression method.
3. **True Positive Indicators**: Only flag values with high contextual evidence:
   - Identifiers adjacent to a person's name, DOB, or "SSN/ID/passport" labels
   - Valid-format national IDs with correct checksums where applicable
   - Identity data clustered together (name + DOB + address) indicating a real record
4. **Suppression Strategies**: For noise, suggest exclusion patterns, context filters, or regex refinements.
5. **Pattern & Behavior**: Differentiate structured reference numbers from genuine personal identifiers via format, checksum, and proximity context.
6. **Pattern Characteristics**: Return entropy and pattern characteristics to justify true positive vs noise classification.
7. **Low-Signal Patterns**: Identify and list all low-context patterns that should be candidates for exclusion rules.
8. **Shannon entropy** (bits per character): Calculate for each matched string. Use it alongside format/checksum validity to judge whether a value is a genuine identifier or a structured non-PII code.
9. **Occurrence frequency**: Count of identical or near-identical matches. 1-5 = unique (investigate); 6-19 = low frequency; 20-99 = medium (likely system-generated); 100+ = high (systemic noise/test data).
10. **PII Totals**: Return the total number of PII findings identified in the chunk. This total must equal the sum of all `count` values in `validated_credentials` plus any identity evidence you classify as part of `credential_pairs` but not already double-counted in `validated_credentials`.

Return ONLY valid JSON:
{
    "credential_summary": {
        "total_credentials_identified": 0,
        "validated_credential_count": 0,
        "credential_pair_count": 0,
        "counting_method": ""
    },
  "noise_patterns": [
    {
      "pattern": "",
      "triggering_sit_rule": "",
      "reason_false_positive": "",
      "occurrence_count": 0,
      "shannon_entropy": 0.0,
      "source_workload": "",
      "noise_signal_keywords": [],
      "suppression_strategy": "",
      "estimated_fp_reduction": 0
    }
  ],
  "validated_credentials": [
    {
      "pattern": "",
      "type": "",
      "triggering_sit_rule": "",
      "validity_status": "VALID_FORMAT|INVALID_CHECKSUM|TRUNCATED|TEST_DATA|INDETERMINATE",
      "shannon_entropy": 0.0,
      "proximity_keywords": [],
      "source_workload": "",
      "content_type": "",
      "confidence_justification": "",
      "count": 0,
      "risk_level": "HIGH|MEDIUM|LOW"
    }
  ],
  "credential_pairs": [
    {
      "components": ["identity_field_1", "identity_field_2"],
      "pair_type": "",
      "source_workload": "",
      "risk_level": "HIGH|MEDIUM|LOW",
      "count": 0
    }
  ],
  "low_frequency_patterns": [
    {
      "pattern": "",
      "count": 0,
      "shannon_entropy": 0.0,
      "reason": "",
      "classification": "NOISE|INVESTIGATE|TRUE_POSITIVE",
      "exclusion_rule_candidate": ""
    }
  ],
  "regex_refinements": [
    {
      "triggering_sit_rule": "",
      "current_regex": "",
      "improved_regex": "",
      "false_positive_reduction": "",
      "false_negative_risk": ""
    }
  ],
  "multi_encoded_artifacts": [
    {
      "pattern": "",
      "encoding_layers": [],
      "reason_false_positive": "",
      "count": 0
    }
  ],
  "workload_context": [
    {
      "workload": "",
      "location": "",
      "content_field": "",
      "full_recipients": [],
      "content_info": "",
      "detected_values_count": 0,
      "user_id": "",
      "sender": "",
      "sensitive_type_name": "",
      "subject": "",
      "risk_assessment": ""
    }
  ],
  "exclusion_rules": [{"rule": "", "scope": "", "reason": ""}],
  "recommendations": "..."
}
'@

    ConsolidationInstruction = @'
You are a **Data Privacy and PII Protection Expert** consolidating SIT tuning findings from multiple analysis chunks into a single professional Noise-Reduction-Focused Markdown report.

Deduplication & Noise Consolidation rules:
- Merge identical noise patterns; flag if the same pattern appears in multiple chunks with the same false-positive reason
- Sum occurrence counts; identify systemic noise sources
- Consolidate overlapping exclusion/suppression strategies
- Prioritize patterns that, if suppressed, eliminate 100+ false positives

Report structure:
1. **Executive Summary**: Total detections analyzed, total PII findings identified, noise detection rate (%), validated true positives remaining, false positive reduction opportunity (%), top 3 quick-win suppressions.
2. **Workload Context Analysis**: Platform/environment types, business processes (HR, CRM, support), and data-handling practices influencing detection tuning.
3. **Noise Pattern Taxonomy** (sources of false positives):
   - Reference/transaction numbers shaped like identifiers (orders, invoices, tickets)
   - Documentation & Example Data (templated test identities, sample records)
   - Format collisions (dates, phone-like sequences, version numbers)
   - Public/business contact data (published phones and addresses)
   - System-generated identifiers and log artifacts
4. **Thematic View** (grouped by identity domain and risk):
   - National Identifiers (SSN, NINO, national ID, tax IDs)
   - Government Documents (passport, driver license)
   - Contact Data (email, phone, postal address)
   - Demographic & Record Data (name + DOB + address clusters)
   - Noise Themes (reference codes, test identities, format collisions)
5. **Noise Pattern Consolidation** (by category and root cause):
   - High-Volume Noise (100+ occurrences; root cause and single suppression strategy; list specific values)
   - Medium Noise (20-99 occurrences; grouped by pattern family; show example values)
   - Low Noise (1-19 occurrences; individual patterns with exact values marked as exclusion rule candidates)
6. **Validated PII Findings** (high-confidence only):
  | Pattern | Type | SIT Rule | Validity | Entropy | Proximity Keywords | Source | Count | Risk Level | Action |
Include:
- Total PII findings aggregated across all chunks, and state the counting basis in one plain sentence when needed.
- Linked identity pairs/clusters identified (elevated re-identification risk flag)
- Validity assessment: VALID_FORMAT / INVALID_CHECKSUM / TRUNCATED / TEST_DATA / INDETERMINATE
- Legitimate exception candidates with justification
- Context evidence supporting the classification
7. **False Positive Suppression Strategy**:
   | Noise Type | Occurrences | Suppression Rule | Test Coverage | Estimated FP Reduction |
8. **Regex Refinements**: Changes that reduce false positives while maintaining sensitivity (prefer checksum/format and proximity gating).
9. **Suppression Implementation Roadmap**: Prioritized regex/exclusion changes with estimated FP reduction impact.
10. **Validation Approach**: How to test suppressions without missing real personal data.
11. **Success Metrics**: FP reduction targets, monitoring cadence, alert thresholds post-tuning.
12. **Before/After Impact Projection**
| Metric | Current (Pre-Suppression) | Projected (Post-Suppression) | Change |
|--------|--------------------------|------------------------------|--------|
| Total detections | | | |
| Total PII findings identified | | | |
| True positives | | | |
| False positives | | | |
| FP rate | | | |
| Alerts per day | | | |
| User notifications per day | | | |
13. **Workload Context Analysis**
| Workload | Location | Sensitive Type | Key Detection Fields | Context | Risk Vectors |
|----------|----------|-----------------|----------------------|---------|--------------|

**Platform-Specific Considerations:**
- **Exchange / Teams Message Body**: Separate genuine personal records from order/ticket references and signatures with published contact info.
- **HR / CRM Exports**: Identity clusters (name + DOB + ID) are high-confidence true positives; apply proximity gating.
- **Re-identification Risk**: Highest where multiple identity fields co-occur; prioritize protecting those clusters.

Output ONLY Markdown. Prioritize noise elimination and false positive reduction over additional pattern discovery.

Additional consolidation rules:
- Produce one canonical consolidated report, not a catalog of disagreements.
- Use `credential_summary.total_credentials_identified` from chunk JSON as the primary basis for total finding counts when available.
- Deduplicate recurring exact artifacts before presenting headline totals.
- If counts differ across chunks, choose one defensible total and state the counting basis in one plain sentence.
'@

    ReportMergeInstruction = @'
You are a **Data Privacy and PII Protection Expert** merging multiple partial Markdown SIT tuning reports into one final Markdown report.

Rules:
- Preserve all material findings from every partial report.
- Combine repeated findings carefully rather than dropping them.
- Build one canonical inventory of unique PII findings, linked identity pairs/clusters, and major noise families before writing the report.
- Make counts additive only when the same exact pattern clearly appears in different partial reports as separate occurrences.
- Prefer explicit per-artifact counts and explicit totals over narrative estimates.
- If partial reports disagree, choose the most defensible canonical total and state the counting basis in one plain sentence.
- Keep the Executive Summary crisp: no long bullet lists of competing totals and no defensive reconciliation language.
- Preserve the same section structure as the original consolidation report.

Language requirements:
- Use direct, declarative language.
- If a counting basis must be stated, use simple wording such as: "PII totals are based on deduplicated unique findings across chunks."

Output ONLY Markdown.
'@
}
