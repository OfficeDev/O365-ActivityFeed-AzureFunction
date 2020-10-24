---
page_type: sample
products:
- office-365
- Sentinel
languages:
- powershellcore
extensions:
  contentType: samples
  createdDate: 8/20/2020 3:00:56 PM
description: "This sample can be used to create a function that ingest DLP.All logs to Sentinel."
---


# Creating Sentinel Analytic Rules based on Office DLP Policies
The script will generate new Analytic rules used for alerting in connection to Office DLP policies. If the script is run more than once it will update the existing rules.


- **MUST** have ingested both SharePoint and Exchange events to Azure Sentinel or rule creation will fail with error 500.

### Running the Script

1. Please use the instructions in the Endpoint DLP preview to deploy the code.
        
## Additional Customization

If you need to customize the KQL query either modify the associated template file ruletemplate.yaml or create your own custom template.



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
