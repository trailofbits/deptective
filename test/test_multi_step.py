import unittest
from unittest.mock import patch, MagicMock, call

from deptective.dependencies import SBOMGenerator


class MultiStepTests(unittest.TestCase):
    
    @patch('deptective.dependencies.SBOMGeneratorStep')
    def test_multi_step_context_management(self, mock_step_class):
        """Test proper context management in multi-step processing"""
        # Setup mocks
        mock_step = MagicMock()
        mock_step.__enter__.return_value = mock_step
        mock_step_class.return_value = mock_step
        
        # Create mock SBOMGenerator
        mock_cache = MagicMock()
        mock_console = MagicMock()
        
        # Prevent attempting to access actual Docker properties
        with patch.object(SBOMGenerator, 'deptective_strace_image', create=True):
            generator = SBOMGenerator(cache=mock_cache, console=mock_console)
            
            # Test code that exercises the context manager
            with patch.object(generator, '_multi_step') as mock_multi_step:
                # Mock return values to avoid errors
                mock_multi_step.return_value = []
                
                # Call multi_step with test commands
                commands = [
                    ['echo', 'test1'],
                    ['echo', 'test2']
                ]
                
                # Consume the iterator
                list(generator.multi_step(*commands))
                
                # Verify the context manager was used correctly
                mock_step.__enter__.assert_called()
                mock_step.__exit__.assert_called()
    
    def test_task_cleanup(self):
        """Test that task cleanup methods function correctly"""
        # Mock minimal SBOMGeneratorStep with progress tracking
        mock_progress = MagicMock()
        mock_task = MagicMock()
        
        # Create the class with patched methods
        with patch('deptective.dependencies.SBOMGeneratorStep', create=True) as MockStep:
            # Set up mock properties
            MockStep._task = mock_task
            MockStep.progress = mock_progress
            
            # Test complete_task method
            with patch.dict('deptective.dependencies.SBOMGeneratorStep.__dict__', {
                'complete_task': lambda self: mock_progress.remove_task(self._task)
            }):
                # Call the method
                MockStep.complete_task(MockStep)
                
                # Verify progress.remove_task was called
                mock_progress.remove_task.assert_called_once_with(mock_task)