# Evaluator custom rules file

package ort.evaluator.rules

import org.ossreviewtoolkit.model.*
import org.ossreviewtoolkit.evaluator.EvaluatorRuleSet
import org.ossreviewtoolkit.evaluator.PackageRule

val ruleSet = EvaluatorRuleSet("TrialRuleSet") {

    packageRule("TRIAL_APACHE_LICENSE_CHECK") {
        require {
            license.contains("Apache-2.0", ignoreCase = true)
        }

        info(
            message = "We are checking Evaluator so this is a trial.",
            howToFix = "No action needed, this is just a test rule for Apache-2.0."
        )
    }
}
