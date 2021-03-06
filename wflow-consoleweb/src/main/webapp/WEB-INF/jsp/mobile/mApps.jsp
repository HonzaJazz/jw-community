<%@ include file="/WEB-INF/jsp/includes/taglibs.jsp" %>
<%@ page import="org.joget.workflow.util.WorkflowUtil"%>
<!DOCTYPE html>
<html class="ui-mobile" manifest="${pageContext.request.contextPath}/web/mobilecache/default">
    <head>
        <title><fmt:message key="mobile.apps.title"/></title>
        <jsp:include page="mScripts.jsp" flush="true"/>
        <script>
            function desktopSite() {
                var path = "${pageContext.request.contextPath}/web/desktop";
                var href = "${pageContext.request.contextPath}/web/desktop";
                Mobile.viewFullSite(path, href);
                return false;
            }
            function showLoading(url) {
                $.mobile.loading('show');
                if (url) {
                    setTimeout(function() {
                        location.href = url;
                    }, 1000);
                    setTimeout(function() {
//                        $.mobile.loading('hide');
                    }, 2000);
                    return false;
                }
            }            
            Mobile.contextPath = "${pageContext.request.contextPath}";
            Mobile.updateCache();
            $("#mobileHome").live("pageshow", function() {
                Mobile.checkNetworkStatus();
            });
        </script>
    </head>

    <body>
        <div id="mobileHome" data-role="page" >
            <div data-role="header" data-position="fixed">
                <h1><fmt:message key="console.header.submenu.label.publishedApps"/></h1>
                <c:set var="isAnonymous" value="<%= WorkflowUtil.isCurrentUserAnonymous() %>"/>
                <c:choose>
                    <c:when test="${isAnonymous}">
                        <a href="${pageContext.request.contextPath}/web/mlogin" data-icon="gear" data-theme="a"><fmt:message key="console.login.label.login"/></a>
                    </c:when>
                    <c:otherwise>
                        <a href="#" onclick="return Mobile.logout()"  data-icon="back" data-theme="a" data-direction="reverse" rel="external"><fmt:message key="console.header.top.label.logout"/></a>
                    </c:otherwise>
                </c:choose> 
                <c:if test="${showDesktopButton ne 'false'}">
                    <a href="#" onclick="return desktopSite()" id="desktop-site" data-role="button" data-icon="home" rel="external"><fmt:message key="mobile.apps.desktop"/></a>
                </c:if>        
            </div>
            <div id="logo"></div>
            <div data-role="content">
                <ul id="appList" data-role="listview" data-filter="false" data-inset="true">
                    <c:forEach items="${appDefinitionList}" var="appDefinition">
                        <c:set var="userviewDefinitionList" value="${appDefinition.userviewDefinitionList}"/>
                        <c:forEach items="${userviewDefinitionList}" var="userviewDefinition">
                            <li>
                                <a onclick="showLoading('${pageContext.request.contextPath}/web/mobile/${appDefinition.id}/${userviewDefinition.id}')" href="${pageContext.request.contextPath}/web/mobile/${appDefinition.id}/${userviewDefinition.id}//landing" rel="external">
                                    <img src="${pageContext.request.contextPath}/web/userview/screenshot/${appDefinition.id}/${userviewDefinition.id}" width="150" border="0" />
                                    <p><b><c:out value="${appDefinition.name}"/></b></p>
                                    <h4><c:out value="${userviewDefinition.name}"/></h4>
                                    <p>
                                        <c:out value="${userviewDefinition.description}"/>
                                        <br>
                                        <fmt:message key="console.app.common.label.version"/> ${appDefinition.version}
                                    </p>
                                </a>
                            </li>
                        </c:forEach>
                    </c:forEach>                    
                </ul>
            </div>		
        </div>
        <div id="online-status"></div>
        <style>
            #getting-started {
                height: 0px;
                width: 0px;
                overflow: hidden;
                z-index: -100;
                position: absolute;
                margin-top: 100%;
            }
        </style>
        <jsp:include page="/WEB-INF/jsp/console/welcome.jsp" flush="true" />          
    </body>

</html>