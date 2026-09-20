import json

from app.parsers import parse_manifests, parse_package_lock, parse_pom, parse_requirements


LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"express": "^4.17.1", "lodash": "4.17.15"}, "devDependencies": {"jest": "^29.0.0"}},
        "node_modules/express": {"version": "4.17.1", "dependencies": {"accepts": "~1.3.7", "qs": "6.7.0"}},
        "node_modules/accepts": {"version": "1.3.8"},
        "node_modules/qs": {"version": "6.7.0"},
        "node_modules/lodash": {"version": "4.17.15"},
        "node_modules/jest": {"version": "29.0.0", "dev": True, "dependencies": {"lodash": "^4"}},
        "node_modules/jest/node_modules/lodash": {"version": "4.17.21", "dev": True},
    },
}


def test_lock_graph_and_flags():
    g = parse_package_lock(json.dumps(LOCK))
    express = g.nodes["npm:express@4.17.1"]
    assert express.direct and not express.dev
    assert express.depends_on == {"npm:accepts@1.3.8", "npm:qs@6.7.0"}
    assert g.nodes["npm:accepts@1.3.8"].direct is False
    assert g.nodes["npm:jest@29.0.0"].dev is True
    assert g.roots == {"npm:express@4.17.1", "npm:lodash@4.17.15", "npm:jest@29.0.0"}


def test_nested_resolution_prefers_nearest_node_modules():
    g = parse_package_lock(json.dumps(LOCK))
    assert g.nodes["npm:jest@29.0.0"].depends_on == {"npm:lodash@4.17.21"}


def test_lock_v1_is_rejected_with_clear_message():
    try:
        parse_package_lock(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    except ValueError as e:
        assert "lockfileVersion 2 or 3" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_requirements():
    g = parse_requirements("# comment\nDjango==3.2.0\nrequests>=2.19.0\nflask\n-r other.txt\nPyYAML[extra]==5.3 ; python_version>'3'\n")
    assert "PyPI:django@3.2.0" in g.nodes
    assert g.nodes["PyPI:requests@2.19.0"].approximate
    assert "PyPI:pyyaml@5.3" in g.nodes
    assert not any(n.name == "flask" for n in g.nodes.values())
    assert any("flask" in w for w in g.warnings)


def test_pom_with_properties_and_scopes():
    pom = """<project xmlns="http://maven.apache.org/POM/4.0.0">
      <properties><log4j.version>2.14.1</log4j.version></properties>
      <dependencies>
        <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>
        <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version><scope>test</scope></dependency>
        <dependency><groupId>x</groupId><artifactId>managed</artifactId></dependency>
      </dependencies></project>"""
    g = parse_pom(pom)
    assert g.nodes["Maven:org.apache.logging.log4j:log4j-core@2.14.1"].dev is False
    assert g.nodes["Maven:junit:junit@4.13"].dev is True
    assert any("managed" in w for w in g.warnings)


def test_package_json_is_skipped_when_lock_in_same_dir():
    files = {"package.json": json.dumps({"dependencies": {"express": "^4.0.0"}}), "package-lock.json": json.dumps(LOCK)}
    g = parse_manifests(files)
    assert "npm:express@4.17.1" in g.nodes and "npm:express@4.0.0" not in g.nodes


def test_no_manifests_warns():
    assert parse_manifests({"README.md": "x"}).warnings
