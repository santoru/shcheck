from shcheck import shcheck
import pytest

def test_no_args_return_help():
    with pytest.raises(SystemExit) as exc:
        shcheck.main()

    # Error code while printing help
    assert exc.value.code == 12
