import unittest

from evaluation.detector_capture import DetectorOutputRecorder


class DetectorCaptureTests(unittest.TestCase):
    def invocation(self, recorder):
        return recorder.record_invocation(
            dataset="sample.parquet",
            window=2,
            row_start=100,
            row_end=200,
            raw_output="THREAT_DETECTED: YES",
            parsed_prediction="ATTACK",
            timestamp="2026-10-12T10:00:00+00:00",
        )

    def test_capture_is_disabled_by_default(self):
        recorder = DetectorOutputRecorder(source="unit-test")
        self.assertIsNone(self.invocation(recorder))
        self.assertEqual(recorder.export_records(), [])

    def test_enabled_capture_preserves_mocked_detector_output(self):
        recorder = DetectorOutputRecorder(
            enabled=True,
            source="mocked-detector-boundary",
        )
        result = self.invocation(recorder)
        self.assertEqual(result["raw_output"], "THREAT_DETECTED: YES")
        self.assertEqual(result["parsed_prediction"], "ATTACK")
        self.assertEqual(result["provenance"], "genuine_recorded")
        self.assertEqual(len(recorder.export_records()), 1)

    def test_non_invocation_never_creates_a_record(self):
        recorder = DetectorOutputRecorder(
            enabled=True,
            source="mocked-detector-boundary",
        )
        recorder.record_non_invocation(
            dataset="sample.parquet",
            window=1,
        )
        self.assertEqual(recorder.export_records(), [])

    def test_disabled_capture_does_not_validate_or_change_result(self):
        recorder = DetectorOutputRecorder(source="unit-test")
        result = recorder.record_invocation(
            dataset="sample.parquet",
            window=1,
            row_start=0,
            row_end=100,
            raw_output=None,
            parsed_prediction=None,
        )
        self.assertIsNone(result)
        self.assertEqual(recorder.export_records(), [])

    def test_enabled_capture_requires_source_and_valid_prediction(self):
        with self.assertRaises(ValueError):
            DetectorOutputRecorder(enabled=True)
        recorder = DetectorOutputRecorder(
            enabled=True,
            source="unit-test",
        )
        with self.assertRaises(ValueError):
            recorder.record_invocation(
                dataset="sample.parquet",
                window=1,
                row_start=0,
                row_end=100,
                raw_output="bad",
                parsed_prediction="MAYBE",
            )
        with self.assertRaises(ValueError):
            recorder.record_invocation(
                dataset="sample.parquet",
                window=1,
                row_start=0,
                row_end=100,
                raw_output=None,
                parsed_prediction=None,
                invocation_status="NOT_INVOKED",
            )


if __name__ == "__main__":
    unittest.main()
