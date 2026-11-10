# Final Report Outline

Use this outline for the course manuscript. The software evidence is linked to the repository artifacts; hardware-only fields remain marked for a real Vivado run.

1. **Title, authors, abstract and keywords**
   - State the CAN-FD IDS problem, the integer feature/decision-tree method, the protocol validator, and measured software results.
2. **Introduction**
   - Automotive CAN-FD threat context, research gap, research question, and four measurable objectives.
3. **Related work**
   - Compare classical CAN IDS methods, timing-based detectors, entropy/statistical methods, and embedded implementations.
   - Include at least 30 verified references before submission.
4. **Preliminaries and problem formulation**
   - CAN-FD frame fields, CRC-17/21, dynamic/fixed stuffing, dual-rate timing, threat model, assumptions, and REQ-01 through REQ-10.
5. **Proposed architecture and methodology**
   - Use `docs/architecture.md`; add listen-only sampler, synchronizer, timing FSM, parser interfaces, and the software-to-hardware mapping.
6. **Mathematical model**
   - Use `docs/mathematical-model.md`; add payload entropy and Gini split equations if they are part of the final claimed method.
7. **Implementation and experimental setup**
   - Python version, dependency versions, GCC version, seeds 42/101/202, generated dataset sizes, and test commands.
   - State clearly that the current artifact is software simulation plus ANSI C conformance, not FPGA synthesis.
8. **Results**
   - Use `results/report_data/canfd_test_frames.csv` and the generated plots. Regenerate them with `PYTHONPATH=. .venv/bin/python scripts/generate_report_artifacts.py` after any dataset or model change.
   - Include confusion matrix, ROC, latency, false positives versus bus load, ablation, and tree complexity.
   - Add Vivado resource/Fmax/timing plots only after real synthesis and implementation.
9. **Discussion, limitations and threats to validity**
   - Synthetic traffic, class imbalance, host benchmark variability, no HIL, no FPGA resource evidence, and no claim of certification.
10. **Conclusion and future work**
    - Summarize each objective with measured values and identify HIL/Vivado/public-dataset validation as future work.
11. **References**
    - Add and verify at least 30 sources; do not treat unverified placeholders as references.
12. **Appendices**
    - CSV schema, source commands, selected C/RTL excerpts, raw run metadata, and member contribution statement.