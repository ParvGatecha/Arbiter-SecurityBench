"""Dynamic attack registry supporting registration and discovery."""

from __future__ import annotations

from collections.abc import Callable

from arbiter_securitybench.attacks.base import Attack
from arbiter_securitybench.attacks.builtin import (
    DirectPromptInjectionAttack,
    InstructionHierarchyAttack,
    MultiTurnJailbreakAttack,
    SensitiveDataLeakageAttack,
    SystemPromptExtractionAttack,
)
from arbiter_securitybench.attacks.models import AttackCategory
from arbiter_securitybench.contracts import (
    AttackType,
    DifficultyLevel,
    DuplicateRegistrationError,
    NotFoundError,
    SecurityCategory,
    SeverityLevel,
    TestCase,
)

_DEFAULT_ATTACK_FACTORIES: dict[str, Callable[[], Attack]] = {
    "builtin.prompt_injection": DirectPromptInjectionAttack,
    "builtin.jailbreak": MultiTurnJailbreakAttack,
    "builtin.system_prompt_extraction": SystemPromptExtractionAttack,
    "builtin.sensitive_data_leakage": SensitiveDataLeakageAttack,
    "builtin.instruction_hierarchy_manipulation": InstructionHierarchyAttack,
}

_CATEGORY_DEFAULT_ATTACK_ID: dict[SecurityCategory, str] = {
    SecurityCategory.PROMPT_INJECTION: "builtin.prompt_injection",
    SecurityCategory.JAILBREAK_RESISTANCE: "builtin.jailbreak",
    SecurityCategory.SYSTEM_PROMPT_EXTRACTION: "builtin.system_prompt_extraction",
    SecurityCategory.SENSITIVE_DATA_LEAKAGE: "builtin.sensitive_data_leakage",
}


def register_attack(
    *,
    registry: AttackRegistry | None = None,
) -> Callable[[type[Attack]], type[Attack]]:
    """Class decorator for dynamically registering an Attack implementation."""

    def _decorator(cls: type[Attack]) -> type[Attack]:
        instance = cls()
        if registry is not None:
            registry.register(instance)
        else:
            if instance.attack_id in _DEFAULT_ATTACK_FACTORIES:
                raise DuplicateRegistrationError(
                    f"Attack {instance.attack_id!r} is already registered globally.",
                    component="attacks.registry",
                    details={"attack_id": instance.attack_id},
                )
            _DEFAULT_ATTACK_FACTORIES[instance.attack_id] = cls
        return cls

    return _decorator


class AttackRegistry:
    """Registry managing modular Attack instances and category/metadata discovery."""

    def __init__(self, *, include_builtins: bool = True) -> None:
        self._attacks: dict[str, Attack] = {}
        if include_builtins:
            for factory in _DEFAULT_ATTACK_FACTORIES.values():
                attack = factory()
                self._attacks[attack.attack_id] = attack

    def register(self, attack: Attack, *, overwrite: bool = False) -> None:
        """Register an Attack instance by its unique attack_id."""
        if attack.attack_id in self._attacks and not overwrite:
            raise DuplicateRegistrationError(
                f"Attack {attack.attack_id!r} is already registered.",
                component="attacks.registry",
                details={"attack_id": attack.attack_id},
            )
        self._attacks[attack.attack_id] = attack

    def get(self, attack_id: str) -> Attack:
        """Retrieve a registered Attack by attack_id."""
        attack = self._attacks.get(attack_id)
        if attack is None:
            raise NotFoundError(
                f"Attack {attack_id!r} is not registered.",
                component="attacks.registry",
                details={"attack_id": attack_id},
            )
        return attack

    def list_attacks(
        self,
        *,
        category: AttackCategory | None = None,
        severity: SeverityLevel | None = None,
        difficulty: DifficultyLevel | None = None,
    ) -> list[Attack]:
        """Discover registered attacks filtered by category, severity, or difficulty."""
        results = [
            a
            for a in self._attacks.values()
            if (category is None or a.category == category)
            and (severity is None or a.severity == severity)
            and (difficulty is None or a.difficulty == difficulty)
        ]
        return sorted(results, key=lambda a: a.attack_id)

    def discover_by_category(self, category: AttackCategory) -> list[Attack]:
        """Return all registered attacks belonging to a given AttackCategory."""
        return self.list_attacks(category=category)

    def resolve_for_test_case(self, test_case: TestCase) -> Attack:
        """Resolve the Attack implementation for a TestCase.

        Resolution order:
        1. Explicit `test_case.metadata["attack_id"]`
        2. Instruction hierarchy tag/metadata hint (`instruction_hierarchy` -> hierarchy attack)
        3. `test_case.attack_type` / `test_case.category` default mapping
        """
        explicit_id = test_case.metadata.get("attack_id")
        if isinstance(explicit_id, str) and explicit_id.strip():
            return self.get(explicit_id.strip())

        is_hierarchy_hint = (
            "instruction_hierarchy" in test_case.tags
            or test_case.metadata.get("attack_category")
            == AttackCategory.INSTRUCTION_HIERARCHY_MANIPULATION.value
        )
        if is_hierarchy_hint and "builtin.instruction_hierarchy_manipulation" in self._attacks:
            return self._attacks["builtin.instruction_hierarchy_manipulation"]

        if test_case.attack_type == AttackType.JAILBREAK and "builtin.jailbreak" in self._attacks:
            return self._attacks["builtin.jailbreak"]

        default_id = _CATEGORY_DEFAULT_ATTACK_ID.get(test_case.category)
        if default_id and default_id in self._attacks:
            return self._attacks[default_id]

        # Fall back to first registered attack matching the mapped SecurityCategory.
        for attack in sorted(self._attacks.values(), key=lambda a: a.attack_id):
            if attack.category.to_security_category() == test_case.category:
                return attack

        raise NotFoundError(
            f"No registered attack found for test case {test_case.test_id!r} "
            f"(category={test_case.category.value!r}).",
            component="attacks.registry",
            details={"test_id": test_case.test_id, "category": test_case.category.value},
        )
