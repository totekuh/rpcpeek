from rpcpeek.known_uuids import UUIDDatabase, DB


class TestUUIDDatabase:
    def test_entry_count(self):
        assert len(DB) >= 59

    def test_samr_lookup(self):
        name, desc = DB.lookup("12345778-1234-ABCD-EF00-0123456789AC")
        assert name == "SAMR"
        assert "Security Account Manager" in desc

    def test_lsarpc_lookup(self):
        name, desc = DB.lookup("12345778-1234-ABCD-EF00-0123456789AB")
        assert name == "LSARPC"

    def test_efsrpc_lookup(self):
        name, desc = DB.lookup("C681D488-D850-11D0-8C52-00C04FD90F7E")
        assert name == "EFSRPC"
        assert "PetitPotam" in desc

    def test_drsuapi_lookup(self):
        name, desc = DB.lookup("E3514235-4B06-11D1-AB04-00C04FC2DCD2")
        assert name == "DRSUAPI"
        assert "DCSync" in desc

    def test_epmapper_lookup(self):
        name, desc = DB.lookup("E1AF8308-5D1F-11C9-91A4-08002B14A0FA")
        assert name == "EPMAPPER"

    def test_fsrvp_lookup(self):
        name, desc = DB.lookup("A8E0653C-2744-4389-A61D-7373DF8B2292")
        assert name == "FSRVP"
        assert "ShadowCoerce" in desc

    def test_dfsnm_lookup(self):
        name, desc = DB.lookup("4FC742E0-4A10-11CF-8273-00AA004AE673")
        assert name == "DFSNM"
        assert "DFSCoerce" in desc

    def test_unknown_uuid(self):
        name, desc = DB.lookup("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
        assert name is None
        assert desc is None

    def test_name_convenience(self):
        assert DB.name("12345778-1234-ABCD-EF00-0123456789AC") == "SAMR"
        assert DB.name("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE") is None

    def test_case_insensitive(self):
        assert DB.name("e3514235-4b06-11d1-ab04-00c04fc2dcd2") == "DRSUAPI"
        assert DB.name("E3514235-4B06-11D1-AB04-00C04FC2DCD2") == "DRSUAPI"

    def test_contains(self):
        assert "12345778-1234-ABCD-EF00-0123456789AC" in DB
        assert "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" not in DB

    def test_all_entries_have_name_and_desc(self):
        for uuid, (name, desc) in DB._by_uuid.items():
            assert name, f"Empty name for {uuid}"
            assert desc, f"Empty description for {uuid}"
            assert len(name) > 0
            assert len(desc) > 0

    def test_separate_instances_independent(self):
        db2 = UUIDDatabase()
        assert len(db2) == len(DB)
        assert db2.name("12345778-1234-ABCD-EF00-0123456789AC") == "SAMR"
