# DRF ViewSet custom action: @action routes to a method with an arbitrary name
# (`run_report`), so the verb-method table never saw it. The standard actions
# (list/create/retrieve/...) are deliberately NOT seeded by name -- they take the
# request object, whose .data/.query_params accessors are already source globs.
import os

from rest_framework.viewsets import ModelViewSet
from rest_framework.decorators import action


class ReportViewSet(ModelViewSet):
    @action(detail=True, methods=["post"])
    def run_report(self, request, report_name):
        os.system("generate-report " + report_name)
        return None
