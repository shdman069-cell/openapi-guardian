from dataclasses import asdict, dataclass


SEVERITIES = ("high", "medium", "low", "info")


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    message: str
    location: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)
