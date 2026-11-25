"""Unit tests for AttackRegistry, dynamic registration, discovery, and deterministic variants."""

from __future__ import annotations

import pytest

from arbiter_securitybench.attacks import (
    AttackCategory,
    AttackRegistry,
    AttackVariant,
    BaseConversationAttack,
    create_deterministic_attack_fixtures,
    register_attack,
)
from arbiter_securitybench.contracts import (
    DifficultyLevel,
    DuplicateRegistrationError,
    NotFoundError,
    SeverityLevel,
)
from conftest import build_test_case


def test_builtin_attacks_cover_all_five_categories() -> None:
    registry = AttackRegistry()
    categories = {a.category for a in registry.list_attacks()}
    assert categories == {
        AttackCategory.PROMPT_INJECTION,
        AttackCategory.JAILBREAK,
        AttackCategory.SYSTEM_PROMPT_EXTRACTION,
        AttackCategory.SENSITIVE_DATA_LEAKAGE,
        AttackCategory.INSTRUCTION_HIERARCHY_MANIPULATION,
    }

    jb = registry.discover_by_category(AttackCategory.JAILBREAK)
    assert len(jb) == 1
    assert jb[0].attack_id == "builtin.jailbreak"

    critical = registry.list_attacks(severity=SeverityLevel.CRITICAL)
    assert [a.attack_id for a in critical] == ["builtin.sensitive_data_leakage"]


def test_dynamic_attack_registration_and_duplicate_detection() -> None:
    registry = AttackRegistry(include_builtins=False)

    @register_attack(registry=registry)
    class CustomProbeAttack(BaseConversationAttack):
        @property
        def attack_id(self) -> str:
            return "custom.probe"

        @property
        def name(self) -> str:
            return "Custom Probe"

        @property
        def category(self) -> AttackCategory:
            return AttackCategory.PROMPT_INJECTION

        @property
        def description(self) -> str:
            return "Custom test attack."

        @property
        def severity(self) -> SeverityLevel:
            return SeverityLevel.LOW

        @property
        def difficulty(self) -> DifficultyLevel:
            return DifficultyLevel.EASY

        def generate_variants(
            self,
            test_case,
            *,
            seed: int = 0,
            max_variants: int = 3,
        ) -> list[AttackVariant]:
            return [
                AttackVariant(
                    variant_id=f"{test_case.test_id}:custom:0",
                    attack_id=self.attack_id,
                    turns=[test_case.input_prompt],
                )
            ][:max_variants]

    assert registry.get("custom.probe").name == "Custom Probe"

    with pytest.raises(DuplicateRegistrationError):
        registry.register(CustomProbeAttack())

    registry.register(CustomProbeAttack(), overwrite=True)

    with pytest.raises(NotFoundError):
        registry.get("missing.attack")


def test_resolve_for_test_case_and_deterministic_variants() -> None:
    registry = AttackRegistry()
    fixtures = create_deterministic_attack_fixtures()

    resolved_ids = [registry.resolve_for_test_case(tc).attack_id for tc in fixtures]
    assert resolved_ids == [
        "builtin.prompt_injection",
        "builtin.jailbreak",
        "builtin.system_prompt_extraction",
        "builtin.sensitive_data_leakage",
        "builtin.instruction_hierarchy_manipulation",
    ]

    # Deterministic variant generation for identical seeds
    pi_attack = registry.get("builtin.prompt_injection")
    v1 = pi_attack.generate_variants(fixtures[0], seed=42, max_variants=2)
    v2 = pi_attack.generate_variants(fixtures[0], seed=42, max_variants=2)
    assert v1 == v2
    assert len(v1) == 2

    # Tag fallback without explicit attack_id metadata
    ih_tc = build_test_case(test_id="tc-ih-tag", tags=["instruction_hierarchy"])
    assert (
        registry.resolve_for_test_case(ih_tc).attack_id
        == "builtin.instruction_hierarchy_manipulation"
    )
