package com.muniao.gatewayservicezuul.filter;

import com.muniao.gatewayservicezuul.service.SsoFeign;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.PRE_DECORATION_FILTER_ORDER;
import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.PRE_TYPE;

/*
        类型	顺序	过滤器	功能
        pre	-3	ServletDetectionFilter	标记处理Servlet的类型
        pre	-2	Servlet30WrapperFilter	包装HttpServletRequest请求
        pre	-1	FormBodyWrapperFilter	包装请求体
        route	1	DebugFilter	标记调试标志
        route	5	PreDecorationFilter	处理请求上下文供后续使用
        route	10	RibbonRoutingFilter	serviceId请求转发
        route	100	SimpleHostRoutingFilter	url请求转发
        route	500	SendForwardFilter	forward请求转发
        post	0	SendErrorFilter	处理有错误的请求响应
        post	1000	SendResponseFilter	处理正常的请求响应
 */
public class TokenFilter extends ZuulFilter
{
    private final Logger logger = LoggerFactory.getLogger(TokenFilter.class);

    @Autowired
    private SsoFeign ssoFeign;

    @Override
    public String filterType()
    {
        return PRE_TYPE; // 可以在请求被路由之前调用
    }

    @Override
    public int filterOrder()
    {
        // filter执行顺序，通过数字指定 ,优先级为0，数字越大，优先级越低
        // PreDecoration之前运行
        return PRE_DECORATION_FILTER_ORDER - 1;
    }

    @Override
    public boolean shouldFilter()
    {
        return true;// 是否执行该过滤器，此处为true，说明需要过滤
    }

    /**
     * 过滤器的具体逻辑
     */
    @Override
    public Object run()
    {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        HttpServletResponse response = ctx.getResponse();

        //访问路径
        String url = request.getRequestURL().toString();
        logger.info("url:" + url);


        //从cookie里面取值（Zuul丢失Cookie的解决方案：https://blog.csdn.net/lindan1984/article/details/79308396）
        String accessToken = request.getParameter("accessToken");
        Cookie[] cookies = request.getCookies();
        if (null != cookies)
        {
            for (Cookie cookie : cookies)
            {
                if ("accessToken".equals(cookie.getName()))
                {
                    accessToken = cookie.getValue();
                }
            }
        }


        //过滤规则：cookie有令牌且存在于Redis，或者访问的是登录页面、登录请求则放行
        if (url.contains("sso-server/sso/loginPage")
                || url.contains("sso-server/sso/login")
                || (!StringUtils.isEmpty(accessToken) && ssoFeign.hasKey(accessToken)))
        {
            ctx.setSendZuulResponse(true);
            ctx.setResponseStatusCode(200);
            return null;
        }
        else
        {
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(401);

            //如果是get请求处理参数，其他请求统统跳转到首页
            String method = request.getMethod();
            if ("GET".equals(method))
            {
                Map<String, String[]> parameterMap = request.getParameterMap();
                if (!parameterMap.isEmpty())
                {
                    List<String> paramList = new ArrayList<>();
                    parameterMap.forEach((paramKey, paramValues) ->
                    {
                        String paramValue;
                        try
                        {
                            paramValue = URLEncoder.encode(paramValues[0], "UTF-8");
                        }
                        catch (UnsupportedEncodingException e)
                        {
                            e.printStackTrace();
                            paramValue = paramValues[0];
                        }
                        paramList.add(paramKey + "=" + paramValue);
                    });
                    String paramPath = String.join("&", paramList);
                    url += "?" + paramPath;
                }


            }
            //重定向到登录页面
            try
            {
                response.sendRedirect("http://localhost:8080/sso-server/sso/loginPage?url=" + url);
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
            return null;
        }
    }

    /*@Override
    public Object run()
    {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();

        logger.info("--->>> TokenFilter {},{}", request.getMethod(), request.getRequestURL().toString());

        String token = request.getParameter("token");// 获取请求的参数

        if (StringUtils.isNotBlank(token))
        {
            ctx.setSendZuulResponse(true); //对请求进行路由
            ctx.setResponseStatusCode(200);
            ctx.set("isSuccess", true);
            return null;
        }
        else
        {
            ctx.setSendZuulResponse(false); //不对其进行路由
            ctx.setResponseStatusCode(400);
            ctx.setResponseBody("token is empty");
            ctx.set("isSuccess", false);
            return null;
        }
    }*/

}
