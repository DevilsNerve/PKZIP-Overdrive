## Summary

- What changed?
- Why is it needed?

## Verification

- [ ] `python -m unittest discover -s tests -v`
- [ ] `python .\wordlist_merger_gpu.py --self-test`
- [ ] Relevant native Windows, Hashcat, or CUDA checks are recorded
- [ ] Linux and Windows workflow jobs pass

## Safety and licensing

- [ ] The change uses only synthetic or explicitly authorized recovery data
- [ ] No archive, extracted hash, wordlist, potfile, password, checkpoint, or
      unredacted log is included
- [ ] Behavior and requirement changes are documented
- [ ] New source is compatible with `AGPL-3.0-only`
- [ ] Any updated DLL has matching source, build details, exports, and SHA-256
