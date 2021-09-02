from src.SHA256 import sha256


def test_sha256():
    assert (
        sha256("abccd").hex()
        == "51a1f5d2734394cd82284a9820c3de5c048a57fe2639f88cdb7267ecd5d2e2c8"
    )
    assert (
        sha256("aaron").hex()
        == "39fdbdb8ddf75a006ffec2a3ba95c3a04ce5517c608a786ef9a042af9843bd8c"
    )
