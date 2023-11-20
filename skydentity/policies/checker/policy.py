from abc import ABC
from typing import Dict

class Policy(ABC):
    """
    A policy is a set of rules that tell what actions can be done on what resources.
    """

    def check_request(self, request):
        """
        Enforces the policy on a request.
        """
        raise NotImplementedError

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        """
        raise NotImplementedError