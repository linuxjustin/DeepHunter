"""Knowledge Graph benchmark datasets — coverage and accuracy of the Knowledge Pack ecosystem.

These benchmarks test that the KnowledgePackRegistry can correctly identify,
relate, and generate investigation plans for technologies.
"""

from deephunter.evaluation.models import (
    BenchmarkDataset,
    BenchmarkEntry,
    BenchmarkInput,
    DatasetType,
    ExpectedOutput,
    ExpectedReasoning,
    ExpectedStep,
)


def _make_graph_entry(
    name: str,
    description: str,
    techs: list[str],
    expected_packs: list[str],
    expected_relationship_types: list[str],
    plan_sections: list[str],
    coverage_areas: list[str],
    tags: list[str],
    difficulty: str = "medium",
) -> BenchmarkEntry:
    return BenchmarkEntry(
        name=name,
        description=description,
        input=BenchmarkInput(
            technologies=techs,
            bug_classes=[],
            attack_surface_areas=coverage_areas,
            description=description,
        ),
        expected=ExpectedOutput(
            planner_steps=[
                ExpectedStep(
                    phase="reconnaissance",
                    title=f"Identify {tech} components",
                    description=f"Discover {tech} infrastructure and endpoints",
                    priority_score=0.85,
                )
                for tech in techs
            ],
            technologies=techs,
            attack_surface=coverage_areas,
            reasoning=ExpectedReasoning(
                hypotheses=[f"{t} is a relevant technology" for t in techs],
                confidence=0.9,
            ),
            checklists=[],
            workflows=[f"Analyze {t} attack surface" for t in techs],
            knowledge_packs=expected_packs,
        ),
        tags=tags,
        difficulty=difficulty,
    )


KNOWLEDGE_GRAPH_DATASET_LARAVEL = BenchmarkDataset(
    id="kg-laravel",
    name="Knowledge Graph — Laravel",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Evaluates knowledge pack graph traversal for Laravel PHP framework",
    tags=["knowledge_graph", "laravel", "php", "framework"],
    entries=[
        _make_graph_entry(
            name="Laravel Technology Identification",
            description="Identify and retrieve knowledge pack for Laravel framework",
            techs=["Laravel", "PHP"],
            expected_packs=["laravel"],
            expected_relationship_types=["uses", "authenticates_with"],
            plan_sections=["Laravel", "authentication", "attack surface"],
            coverage_areas=["Authentication", "Authorization", "Database"],
            tags=["knowledge_graph", "laravel", "identification"],
            difficulty="easy",
        ),
        _make_graph_entry(
            name="Laravel Authentication Investigation",
            description="Generate investigation plan for Laravel authentication vulnerabilities",
            techs=["Laravel"],
            expected_packs=["laravel"],
            expected_relationship_types=["uses"],
            plan_sections=["Laravel", "authentication", "session"],
            coverage_areas=["Authentication", "Session Management"],
            tags=["knowledge_graph", "laravel", "authentication"],
            difficulty="medium",
        ),
    ],
)


KNOWLEDGE_GRAPH_DATASET_NODEJS = BenchmarkDataset(
    id="kg-nodejs",
    name="Knowledge Graph — Node.js",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Evaluates knowledge pack graph traversal for Node.js ecosystem",
    tags=["knowledge_graph", "nodejs", "javascript", "framework"],
    entries=[
        _make_graph_entry(
            name="Node.js Express Identification",
            description="Identify knowledge packs for Node.js Express application",
            techs=["Express", "Node.js"],
            expected_packs=["express"],
            expected_relationship_types=["uses"],
            plan_sections=["Express", "routing", "middleware"],
            coverage_areas=["Routing", "Middleware", "Authentication"],
            tags=["knowledge_graph", "express", "identification"],
            difficulty="easy",
        ),
        _make_graph_entry(
            name="REST API Technology Stack",
            description="Identify full REST API technology stack from Node.js components",
            techs=["Express", "REST"],
            expected_packs=["express", "rest"],
            expected_relationship_types=["uses", "integrates_with"],
            plan_sections=["Express", "REST", "authentication"],
            coverage_areas=["API Security", "Authentication", "Input Validation"],
            tags=["knowledge_graph", "express", "rest", "api"],
            difficulty="medium",
        ),
    ],
)


KNOWLEDGE_GRAPH_DATASET_DATABASE = BenchmarkDataset(
    id="kg-database",
    name="Knowledge Graph — Databases",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Evaluates knowledge pack graph for database technologies",
    tags=["knowledge_graph", "database", "postgresql", "mysql", "mongodb"],
    entries=[
        _make_graph_entry(
            name="PostgreSQL Technology Identification",
            description="Identify PostgreSQL knowledge pack and its relationships",
            techs=["PostgreSQL"],
            expected_packs=["postgresql"],
            expected_relationship_types=["stores_data_in"],
            plan_sections=["PostgreSQL", "SQL injection", "authentication"],
            coverage_areas=["Database", "SQL Injection", "Authentication"],
            tags=["knowledge_graph", "postgresql", "database"],
            difficulty="easy",
        ),
        _make_graph_entry(
            name="Database Attack Surface",
            description="Generate investigation plan for database attack surface",
            techs=["PostgreSQL", "MySQL", "MongoDB"],
            expected_packs=["postgresql", "mysql", "mongodb"],
            expected_relationship_types=["stores_data_in"],
            plan_sections=["PostgreSQL", "MySQL", "MongoDB", "injection"],
            coverage_areas=["SQL Injection", "NoSQL Injection", "Authentication"],
            tags=["knowledge_graph", "database", "attack_surface"],
            difficulty="medium",
        ),
    ],
)


KNOWLEDGE_GRAPH_DATASET_CLOUD = BenchmarkDataset(
    id="kg-cloud",
    name="Knowledge Graph — Cloud",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Evaluates knowledge pack graph for cloud providers",
    tags=["knowledge_graph", "cloud", "aws", "azure", "gcp"],
    entries=[
        _make_graph_entry(
            name="AWS Technology Identification",
            description="Identify AWS knowledge pack and its service relationships",
            techs=["AWS"],
            expected_packs=["aws"],
            expected_relationship_types=["deployed_on", "integrates_with"],
            plan_sections=["AWS", "IAM", "S3", "EC2"],
            coverage_areas=["Cloud Security", "IAM", "Storage"],
            tags=["knowledge_graph", "aws", "cloud"],
            difficulty="easy",
        ),
        _make_graph_entry(
            name="Cloud Architecture Investigation",
            description="Generate investigation plan for multi-cloud architecture",
            techs=["AWS", "Azure", "GCP"],
            expected_packs=["aws", "azure", "gcp"],
            expected_relationship_types=["deployed_on"],
            plan_sections=["AWS", "Azure", "GCP", "IAM", "storage"],
            coverage_areas=["IAM", "Storage", "Networking", "Serverless"],
            tags=["knowledge_graph", "cloud", "multi-cloud"],
            difficulty="hard",
        ),
    ],
)


KNOWLEDGE_GRAPH_DATASET_GRAPH_TRAVERSAL = BenchmarkDataset(
    id="kg-traversal",
    name="Knowledge Graph — Traversal",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Evaluates graph traversal depth and relationship following",
    tags=["knowledge_graph", "traversal", "relationships"],
    entries=[
        _make_graph_entry(
            name="Laravel MySQL Stack Traversal",
            description="Traverse from Laravel to its database dependencies",
            techs=["Laravel", "MySQL"],
            expected_packs=["laravel", "mysql"],
            expected_relationship_types=["uses", "stores_data_in"],
            plan_sections=["Laravel", "MySQL", "authentication", "database"],
            coverage_areas=["Authentication", "Database", "SQL Injection"],
            tags=["knowledge_graph", "traversal", "stack"],
            difficulty="medium",
        ),
        _make_graph_entry(
            name="Kubernetes Docker Stack",
            description="Traverse container orchestration stack",
            techs=["Kubernetes", "Docker"],
            expected_packs=["kubernetes", "docker"],
            expected_relationship_types=["orchestrated_by", "containerized_by"],
            plan_sections=["Kubernetes", "Docker", "containers", "orchestration"],
            coverage_areas=["Container Security", "Orchestration", "Networking"],
            tags=["knowledge_graph", "traversal", "kubernetes", "docker"],
            difficulty="medium",
        ),
        _make_graph_entry(
            name="Graph Depth Three",
            description="Verify graph traversal reaches depth 3 correctly",
            techs=["Express", "PostgreSQL", "Docker"],
            expected_packs=["express", "postgresql", "docker"],
            expected_relationship_types=["uses", "stores_data_in", "containerized_by"],
            plan_sections=["Express", "PostgreSQL", "Docker", "API", "database"],
            coverage_areas=["API Security", "Database", "Container"],
            tags=["knowledge_graph", "traversal", "depth"],
            difficulty="hard",
        ),
    ],
)


def get_knowledge_graph_datasets() -> list[BenchmarkDataset]:
    return [
        KNOWLEDGE_GRAPH_DATASET_LARAVEL,
        KNOWLEDGE_GRAPH_DATASET_NODEJS,
        KNOWLEDGE_GRAPH_DATASET_DATABASE,
        KNOWLEDGE_GRAPH_DATASET_CLOUD,
        KNOWLEDGE_GRAPH_DATASET_GRAPH_TRAVERSAL,
    ]


def get_knowledge_graph_dataset(name: str) -> BenchmarkDataset | None:
    for ds in get_knowledge_graph_datasets():
        if ds.name == name or ds.id == name:
            return ds
    return None