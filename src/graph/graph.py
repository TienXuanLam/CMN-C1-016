"""AgentCore Platform v1.0"""

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.schemas.trust_level import TrustLevel

from src.nodes.pre_process_node import PreProcessNode
from src.nodes.main_node import MainNode
from src.nodes.post_process_node import PostProcessNode
from src.schemas.state import CodeGenerationState


class CodeGenerationGraph(AgentBaseGraph):
    """Fixed-pipeline graph for CMN-C1-016 CodeGenerationAgent.

    3-slot SDK pipeline:
        pre_process  : PreProcessNode  — input validation, PII masking (S-2), spec parsing
        main         : MainNode        — LLM code generation + output formatting
        post_process : PostProcessNode — output assembly + domain S-3 credential scan

    Runtime config keys (config/config.yaml via self.config): max_spec_length,
    llm_temperature, llm_max_tokens, timeout_s, and max_retry. Language,
    framework, style, and testing requirements are expressed in user_input.

    Prompt contract:
        MainNode appends sanitized plain text to fixed project-owned
        instructions. No caller-controlled template or template engine exists.
    """

    required_trust_level = TrustLevel.VERIFIED_EXTERNAL

    @property
    def name(self) -> str:
        return "CodeGenerationAgent"

    @property
    def state_schema(self) -> type:
        return CodeGenerationState

    def register_nodes(self) -> None:
        super().register_nodes()  # injects InitializeNode + FinalizeNode
        # max_spec_length is deployment-owned, never caller-controlled.
        self._nodes["pre_process"] = PreProcessNode(max_spec_length=self.config.get("max_spec_length", 4000))
        self._nodes["main"] = MainNode(
            llm_temperature=float(self.config.get("llm_temperature", 0.2)),
            llm_max_tokens=int(self.config.get("llm_max_tokens", 4096)),
            timeout_s=int(self.config.get("timeout_s", 30)),
            max_retry=int(self.config.get("max_retry", 3)),
        )
        self._nodes["post_process"] = PostProcessNode()
