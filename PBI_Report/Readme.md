# Summary of the Step-by-Step Guided Walkthrough

This guide provides an overview of how to get started with new tooling in Power BI reports, focusing on steps to configure and customize reports for organizational needs.

### Key Steps:

1. **Download and Open the Report**:
   - Obtain the latest report version and open it in Power BI Desktop.
   - Approve the use of ArcGIS Maps if prompted.

2. **Authentication**:
   - Authenticate with `https://api.security.microsoft.com` using an Organizational account.
   - Repeat authentication for `https://api.security.microsoft.com/api/advancedhunting`.

3. **Data Loading**:
   - Allow the system to collect data, which may take time in larger environments.

4. **Review and Update Reports**:
   - Update KPI diagrams and high-level descriptions to align with your organization’s objectives.
   - Filter reports to include only the required Sensitive Information Types (SITs).

5. **Customize Report Components**:
   - Modify diagrams, KPI measurements, and incident views to reflect relevant data.
   - Ensure the mapping of labeled content by updating the MIPLabel table with correct label names and GUIDs.

6. **Update Critical Systems Access**:
   - Use the SensitiveSystems query to update URLs for systems with high business impact.
   - Manually add URLs as needed and apply the changes.

7. **Operational Scope Review**:
   - Verify the operational scope, ensuring that sensitive information processing is accurately represented for legal entities.

8. **Additional Reports**:
   - Customize additional reports, such as those for Trust & Reputation, Company & Shareholder Value, and incident analysis.
   - Set target values and review incident reporting metrics.

9. **Power BI Online Integration**:
   - Set up Power BI Online to enable secure, role-based access to the dashboard with scheduled data refreshes.

### Final Configuration:

- **Incident Data Customization**: Adjust the time frame for incident data to fit organizational requirements.
- **Sensitive Information Capture**: Set up custom DLP policies to capture sensitive data in Exchange and SharePoint Online.

For detailed steps and configurations, refer to the complete guide. https://techcommunity.microsoft.com/t5/security-compliance-and-identity/how-to-build-the-microsoft-purview-extended-report-experience/ba-p/4122028

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
