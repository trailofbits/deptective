class SBOMGenerationError(RuntimeError):
    pass


class PackageResolutionError(SBOMGenerationError):
    pass


class PackageDatabaseNotFoundError(PackageResolutionError):
    pass
