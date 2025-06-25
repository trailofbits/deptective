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
        with patch('deptective.cli.mkdtemp') as mock_mkdtemp, \
             patch('deptective.cli.rmtree') as mock_rmtree, \
             patch('deptective.cli.SBOMGenerator'), \
             patch('deptective.cli.load_cache'), \
             patch('sys.argv', ['deptective', 'echo', 'test']):
            
            mock_mkdtemp.return_value = '/tmp/deptective-test'
            # Mock an exception to return immediately
            with patch('deptective.cli.main', return_value=0):
                main()
            
            # Verify temporary directory was created
            mock_mkdtemp.assert_called_once_with(prefix="deptective-")

    def test_log_dir_override(self):
        """Test that the --force option correctly handles log directory"""
        with patch('deptective.cli.rmtree') as mock_rmtree, \
             patch('deptective.cli.load_cache'), \
             patch('deptective.cli.SBOMGenerator'), \
             patch('sys.argv', ['deptective', '--log-dir', '/tmp/test-logs', '--force', 'echo', 'test']), \
             patch('pathlib.Path.exists', return_value=True):
            
            # Call into the function that processes arguments
            args = main()
            
            # Since we've patched Path.exists to return True and provided --force,
            # rmtree should be called
            mock_rmtree.assert_called_once()

    def test_log_dir_error_handling(self):
        """Test the error path with existing log directory without force flag"""
        with patch('deptective.cli.load_cache'), \
             patch('deptective.cli.SBOMGenerator'), \
             patch('deptective.cli.logger') as mock_logger, \
             patch('sys.argv', ['deptective', '--log-dir', '/tmp/test-logs', 'echo', 'test']), \
             patch('os.path.exists', return_value=True), \
             patch('deptective.cli.Path.exists', return_value=True):
            
            # Run main and capture return code
            result = main()
            
            # Verify error was logged and function returned error code
            mock_logger.error.assert_called_once()
            self.assertEqual(result, 1)