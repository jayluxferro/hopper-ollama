"""
Minimal mock of Hopper's Document API for testing HopperOllama outside Hopper.
Used when running tests (python in sys.executable); Hopper injects the real Document when run in Hopper.
"""


class MockDoc:
    """Single document mock."""

    def __init__(self, name: str = "mock_binary", entry_point: int = 0x1000):
        self._name = name
        self._entry_point = entry_point

    def getDocumentName(self):
        return self._name

    def getExecutableFilePath(self):
        return f"/tmp/{self._name}"

    def getEntryPoint(self):
        return self._entry_point

    def getSegmentCount(self):
        return 1

    def backgroundProcessActive(self):
        return False

    def getAddressForName(self, name):
        if name and name.strip().lower().startswith("0x"):
            try:
                return int(name.strip().replace("0x", ""), 16)
            except ValueError:
                return None
        return None

    def getSegmentAtAddress(self, addr):
        return None  # Tests patch get_hopper_context so this is not used

    def log(self, msg):
        pass


# Default docs for tests
_default_doc = MockDoc("main_binary")
_extra_doc = MockDoc("other_binary", 0x2000)


class Document:
    """Mock Document class with getCurrentDocument and getAllDocuments."""

    _current = _default_doc
    _all = [_default_doc, _extra_doc]

    @classmethod
    def getCurrentDocument(cls):
        return cls._current

    @classmethod
    def getAllDocuments(cls):
        return list(cls._all)

    @classmethod
    def set_current_for_tests(cls, doc_index: int):
        """Test helper: set which document is 'current' by index."""
        if 0 <= doc_index < len(cls._all):
            cls._current = cls._all[doc_index]
