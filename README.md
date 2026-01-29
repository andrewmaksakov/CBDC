# Privacy-Preserving Financial Surveillance: An Architectural Framework for CBDC Implementation

**Preprint v1.1.0 | January 2026**

Murad Farzulla — [Farzulla Research](https://farzulla.org) — [ORCID](https://orcid.org/0009-0002-7164-8704)

**DOI:** [10.5281/zenodo.17917938](https://doi.org/10.5281/zenodo.17917938)

## Abstract

This paper challenges the assumption that comprehensive transaction surveillance is necessary for CBDC financial stability and crime prevention. It proposes an alternative architecture achieving 87–95% of surveillance-based detection effectiveness while preserving complete transactional privacy. The framework operates through anonymized pattern detection, transaction-level intervention, and opt-in deanonymization — demonstrating that the surveillance–security trade-off is a false dichotomy.

## Repository Structure

```
main.tex          # LaTeX source
references.bib    # BibTeX bibliography
pet_aml_sim.py    # PET AML stack simulation (Section 5.4)
```

## Simulation

The `pet_aml_sim.py` script simulates the PET AML stack described in Section 5.4, including PSI watchlist screening, ZK policy proof generation/verification, secure MPC risk propagation, and queueing delays. No external dependencies — pure Python 3.

```bash
python pet_aml_sim.py --days 2 --tx-per-day 20000 --psps 8 --seed 7
```

Run `python pet_aml_sim.py --help` for all options.

## Building the Paper

Requires a LaTeX distribution (e.g., TeX Live, MiKTeX) with `pdflatex`, `bibtex`, and standard packages.

```bash
pdflatex main
bibtex main
pdflatex main
pdflatex main
```

**Note:** The document references `farzulla-logo.pdf` and `zenodo-logo.pdf` logo files which are not included in this repository. Comment out or replace the `\farzullalogo` and `\zenodologo` commands in `main.tex` if building without them.

## License

- **Paper content:** [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/)
- **Repository:** [MIT](LICENSE)

## Citation

```bibtex
@article{Farzulla2026CBDC,
  author  = {Farzulla, Murad},
  title   = {Privacy-Preserving Financial Surveillance: An Architectural Framework for {CBDC} Implementation},
  journal = {Farzulla Research Preprint},
  year    = {2026},
  doi     = {10.5281/zenodo.17917938},
  note    = {Preprint v1.1.0}
}
```
