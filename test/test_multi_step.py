import tempfile
import time
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch, MagicMock

from deptective.dependencies import SBOMGenerator, SBOMGeneratorStep


class MultiStepTests(TestCase):
    def test_multi_step_context_management(self):
        """Test that context managers are properly used in multi-step processing"""
        # Create a mock SBOMGenerator
        mock_cache = MagicMock()
        mock_console = MagicMock()
        generator = SBOMGenerator(cache=mock_cache, console=mock_console)
        
        # Mock step methods to avoid actual execution
        with patch.object(SBOMGeneratorStep, '__enter__', return_value=MagicMock()), \
             patch.object(SBOMGeneratorStep, '__exit__'), \
             patch.object(SBOMGeneratorStep, 'find_feasible_sboms'), \
             patch.object(SBOMGeneratorStep, 'complete_task'):
            
            # Test multi_step with mock commands
            commands = [
                ['echo', 'test1'],
                ['echo', 'test2']
            ]
            
            # Convert to iterator and verify it can be processed without errors
            sbom_iter = generator.multi_step(*commands)
            list(sbom_iter)  # Just consume the iterator
            
            # The key test here is that no exceptions were raised during context management

    def test_progress_task_cleanup(self):
        """Test that progress tasks are properly cleaned up"""
        # Create a mock SBOMGenerator
        mock_cache = MagicMock()
        mock_console = MagicMock()
        generator = SBOMGenerator(cache=mock_cache, console=mock_console)
        
        # Create a test step
        test_step = SBOMGeneratorStep(generator, "test", ["arg1"])
        
        # Record initial state
        initial_task = test_step._task
        self.assertIsNotNone(initial_task)
        
        # Call complete_task
        test_step.complete_task()
        
        # Verify task was removed
        self.assertIsNone(test_step._task)
        
        # Test that _cleanup also calls complete_task
        test_step = SBOMGeneratorStep(generator, "test", ["arg1"])
        test_step._cleanup()
        self.assertIsNone(test_step._task)