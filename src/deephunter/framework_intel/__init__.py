"""Framework Intelligence — correlates technologies into framework stacks
and generates attack surface profiles.

A "framework stack" is an ordered set of technologies that together
define a coherent application platform (e.g. Nginx + PHP + Laravel).
"""

from deephunter.framework_intel.correlator import FrameworkCorrelator
from deephunter.framework_intel.models import (
    ApplicationProfile,
    AttackSurfaceProfile,
    FrameworkStack,
    StackCorrelation,
)
from deephunter.framework_intel.profiler import AttackSurfaceProfiler

__all__ = [
    "FrameworkCorrelator",
    "FrameworkStack",
    "StackCorrelation",
    "ApplicationProfile",
    "AttackSurfaceProfiler",
    "AttackSurfaceProfile",
]
