import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add the parent directory to the Python path to allow for package imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.salesforce_client import SalesforceOAuthClient

class TestSalesforceOAuthClient(unittest.TestCase):

    def setUp(self):
        """Set up a test client before each test."""
        self.client = SalesforceOAuthClient(
            client_id='test_client_id',
            client_secret='test_client_secret',
            username='test_user',
            password='test_password',
            security_token='test_token'
        )

    @patch('agents.salesforce_client.requests.post')
    @patch('agents.salesforce_client.SalesforceOAuthClient._get_org_id')
    def test_connect_success(self, mock_get_org_id, mock_post):
        """Test a successful connection to Salesforce."""
        # Arrange
        # Mock the response from the Salesforce token endpoint
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'access_token': 'fake_access_token',
            'instance_url': 'https://fake.salesforce.com'
        }
        mock_post.return_value = mock_response

        # Mock the org id call
        mock_get_org_id.return_value = 'fake_org_id'

        # Act
        result = self.client.connect()

        # Assert
        self.assertTrue(result)
        self.assertEqual(self.client.access_token, 'fake_access_token')
        self.assertEqual(self.client.instance_url, 'https://fake.salesforce.com')
        self.assertEqual(self.client.org_id, 'fake_org_id')

        # Verify that requests.post was called correctly
        mock_post.assert_called_once_with(
            'https://login.salesforce.com/services/oauth2/token',
            data={
                'grant_type': 'password',
                'client_id': 'test_client_id',
                'client_secret': 'test_client_secret',
                'username': 'test_user',
                'password': 'test_passwordtest_token' # Password + Token
            },
            timeout=30
        )

    @patch('agents.salesforce_client.requests.post')
    def test_connect_failure(self, mock_post):
        """Test a failed connection to Salesforce."""
        # Arrange
        # Mock a failed response from the Salesforce token endpoint
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            'error': 'invalid_grant',
            'error_description': 'authentication failure'
        }
        mock_post.return_value = mock_response

        # Act
        result = self.client.connect()

        # Assert
        self.assertFalse(result)
        self.assertIsNone(self.client.access_token)
        self.assertIsNone(self.client.instance_url)

if __name__ == '__main__':
    unittest.main()
