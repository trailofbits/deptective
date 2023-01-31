import logging

from .dependencies import SBOMGenerator


logger = logging.getLogger(__name__)

done_packages = set()


def main():
    for sbom in SBOMGenerator().main():
        print(sbom)


if __name__ == "__main__":
    main()
