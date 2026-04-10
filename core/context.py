class Context:
    def __init__(self, base_path):
        self.base_path = base_path

        # Runtime flags
        self.use_ai = False
        self.verbose = False

        # Pipeline components
        self.collectors = []
        self.analyzers = []
        self.correlator = None
        self.output = None