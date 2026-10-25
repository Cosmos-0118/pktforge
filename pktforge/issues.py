"""Findings reported by spec loading, building and linting."""
from dataclasses import dataclass, asdict

ERROR, WARNING, INFO = "error", "warning", "info"


@dataclass
class Issue:
    code: str
    severity: str
    message: str
    where: str = ""
    fix: str = ""

    def as_dict(self):
        return {k: v for k, v in asdict(self).items() if v}

    def __str__(self):
        loc = " [%s]" % self.where if self.where else ""
        fix = "\n      fix: %s" % self.fix if self.fix else ""
        return "%-7s %s%s %s%s" % (self.severity.upper(), self.code, loc, self.message, fix)


class SpecError(Exception):
    """A problem in the spec that stops the build; carries Issues."""

    def __init__(self, issues):
        self.issues = issues if isinstance(issues, list) else [issues]
        super().__init__("; ".join(i.message for i in self.issues))


def has_errors(issues):
    return any(i.severity == ERROR for i in issues)
