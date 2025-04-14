import os
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch, MagicMock

from deptective.cli import main
from deptective.dependencies import SBOMGenerationError, PackageResolutionError


class LoggingTests(TestCase):
    def test_temporary_log_dir_creation(self):
        """Test that a temporary log directory is created when no log_dir is specified"""
        with patch('deptective.cli.TemporaryDirectory') as mock_tempdir, \
             patch('deptective.cli.SBOMGenerator'), \
             patch('deptective.cli.load_cache'):
            mock_tempdir.return_value.name = '/tmp/deptective-test'
            # Mock an exception to test error path
            with patch('deptective.cli.SBOMGenerator.main') as mock_main:
                mock_main.side_effect = Exception('Test exception')
                with self.assertRaises(Exception):
                    main()
            # Verify temporary directory was created
            mock_tempdir.assert_called_once()

    def test_log_dir_override(self):
        """Test that the --force option deletes an existing log directory"""
        with tempfile.TemporaryDirectory() as tempdir:
            log_dir = Path(tempdir) / 'test-logs'
            log_dir.mkdir()
            # Create a test file in the log directory
            test_file = log_dir / 'test.txt'
            test_file.write_text('test content')
            
            with patch('sys.argv', ['deptective', '--log-dir', str(log_dir), '--force', 'echo', 'test']), \
                 patch('deptective.cli.load_cache'), \
                 patch('deptective.cli.SBOMGenerator'):
                # Mock an early exit to avoid actual command execution
                with patch('deptective.cli.SBOMGenerator.main'):
                    main()
                    
            # Verify directory exists but was cleaned (test file should be gone)
            self.assertTrue(log_dir.exists())
            self.assertFalse(test_file.exists())

    def test_saving_partial_sbom(self):
        """Test that partial SBOM is saved when an error occurs"""
        with tempfile.TemporaryDirectory() as tempdir:
            log_dir = Path(tempdir) / 'test-logs'
            
            # Create mock partial SBOM
            mock_sbom = ['package1', 'package2']
            error = PackageResolutionError(
                "Test error",
                command_output=b"test output",
                partial_sbom=mock_sbom
            )
            
            with patch('sys.argv', ['deptective', '--log-dir', str(log_dir), 'echo', 'test']), \
                 patch('deptective.cli.load_cache'), \
                 patch('deptective.cli.SBOMGenerator'):
                # Mock an error during execution
                with patch('deptective.cli.SBOMGenerator.main') as mock_main:
                    mock_main.side_effect = error
                    with self.assertRaises(SBOMGenerationError):
                        main()
            
            # Verify files were created
            sbom_file = log_dir / 'most_promising_sbom.txt'
            output_file = log_dir / 'final_output.txt'
            
            self.assertTrue(sbom_file.exists())
            self.assertTrue(output_file.exists())
            
            # Verify content
            self.assertEqual(sbom_file.read_text(), 'package1\npackage2')
            self.assertEqual(output_file.read_bytes(), b'test output')