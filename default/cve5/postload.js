defaultTabs.sourceTab.getValue = function () {
    var res = JSON.parse(sourceEditor.getSession().getValue());
    res = cveFixForVulndesk(res);
    return res;
};
