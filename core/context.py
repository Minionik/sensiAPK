class Context:
    def __init__(self, base_path):
        self.base_path = base_path

        # Runtime flags
        self.use_ai  = False
        self.verbose = False

        # Optional: path to decompiled APK folder (Jadx / Apktool output)
        self.apk_dir = None

        # Pipeline components
        self.collectors = []
        self.analyzers  = []
        self.correlator = None
        self.output     = None

        # Populated by engine after scan — used for HTML report
        self.phase1_findings = []
        self.code_findings   = []
