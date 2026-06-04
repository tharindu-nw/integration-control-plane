/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 *
 */

import React, {useEffect, useState} from 'react';
import { Switch, Route, BrowserRouter as Router, Redirect } from 'react-router-dom';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import CssBaseline from '@material-ui/core/CssBaseline';
import Hidden from '@material-ui/core/Hidden';
import Typography from '@material-ui/core/Typography';
import Box from '@material-ui/core/Box';
import CircularProgress from '@material-ui/core/CircularProgress';
import Snackbar from '@material-ui/core/Snackbar';
import { useAuthContext } from "@asgardeo/auth-react";
import { Constants } from '../utils/Constants';
import Navigator from './layout/Navigator';
import Content from './layout/Content';
import Header from './layout/Header';
import ProxyService from '../pages/ProxyService';
import RegistryResources from '../pages/RegistryResources';
import Endpoints from '../pages/Endpoints';
import Nodes from '../pages/nodes/Nodes';
import InboundEndpoints from '../pages/InboundEndpoints';
import MessageProcessors from '../pages/MessageProcessors'
import MessageStores from '../pages/MessageStores'
import APIs from '../pages/APIs'
import Templates from '../pages/Templates'
import Sequences from '../pages/Sequences';
import Tasks from '../pages/Tasks';
import LocalEntries from '../pages/LocalEntries';
import DataServices from '../pages/DataServices';
import Connectors from '../pages/Connectors';
import CarbonApplications from '../pages/CarbonApplications';
import LogFiles from '../pages/LogFiles'
import LogConfigs from '../pages/LogConfigs'
import Users from '../pages/Users'
import Roles from '../pages/Roles';
import AddUsers from '../pages/AddUsers'
import AddRoles from '../pages/AddRoles';
import AddLogConfig from '../pages/AddLogConfig'
import DataSources from '../pages/Datasources';
import Services from '../pages/Services';
import SiddhiApplications from '../pages/SiddhiApplications';
import Sources from '../pages/Sources';
import Sinks from '../pages/Sinks';
import Queries from '../pages/Queries';
import Stores from '../pages/Stores';
import Windows from '../pages/Windows';
import Aggregations from '../pages/Aggregations';
import AuthManager from '../auth/AuthManager';
import { setIsRefreshed } from '../redux/Actions';
import { useDispatch } from 'react-redux';
import UpdatePassword from "../pages/UpdatePassword";
import Listeners from '../pages/Listener';

const drawerWidth = 256;

const styles = (theme) => ({
    root: {
        display: 'flex',
        minHeight: '100vh',
    },
    drawer: {
        [theme.breakpoints.up('sm')]: {
            width: drawerWidth,
            flexShrink: 0,
        },
    },
    app: {
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
    },
    main: {
        flex: 1,
        padding: theme.spacing(4, 4),
        background: '#eaeff1',
    },
    footer: {
        padding: theme.spacing(2),
        background: '#eaeff1',
    },
});

function Layout(props) {
    const { classes } = props;
    const [mobileOpen, setMobileOpen] = React.useState(false);
    const { signIn } = useAuthContext();
    const dispatch = useDispatch();

    const isSsoUser = AuthManager.getUser()?.sso;
    const { state, trySignInSilently } = useAuthContext();
    // For SSO users the session is only confirmed once the Asgardeo SDK holds
    // valid tokens. Non-SSO users are considered checked from the start.
    const [ssoSessionChecked, setSsoSessionChecked] = useState(!isSsoUser);
    const [ssoSessionExpired, setSsoSessionExpired] = useState(false);
    const [idpUnavailable, setIdpUnavailable] = useState(false);

    const handleDrawerToggle = () => {
        setMobileOpen(!mobileOpen);
    };

    useEffect(() => {
        if (AuthManager.getUser()?.sso) {
            signIn()
        }
        dispatch(setIsRefreshed(true))
    },[])

    // Show a single banner when the identity provider cannot be reached to
    // validate the session, instead of letting every page fail silently.
    useEffect(() => {
        const handler = () => setIdpUnavailable(true);
        window.addEventListener(Constants.IDP_UNAVAILABLE_EVENT, handler);
        return () => window.removeEventListener(Constants.IDP_UNAVAILABLE_EVENT, handler);
    }, [])

    // Reconcile the local session cookie with the Asgardeo session state. With
    // web worker storage the tokens are lost on a browser reload while the
    // session cookie survives, which previously left the UI stuck on a loading
    // screen. Attempt to silently restore the session and fall back to the
    // login page when it can no longer be authenticated.
    useEffect(() => {
        if (!isSsoUser || ssoSessionChecked) {
            return;
        }
        if (state.isAuthenticated) {
            setSsoSessionChecked(true);
            return;
        }
        if (state.isLoading) {
            // Wait until the SDK finishes initializing before deciding.
            return;
        }
        let isActive = true;
        trySignInSilently()
            .then(response => {
                if (!isActive) {
                    return;
                }
                if (response) {
                    setSsoSessionChecked(true);
                } else {
                    AuthManager.discardSession();
                    setSsoSessionExpired(true);
                }
            })
            .catch(() => {
                if (isActive) {
                    AuthManager.discardSession();
                    setSsoSessionExpired(true);
                }
            });
        return () => { isActive = false; };
    }, [isSsoUser, ssoSessionChecked, state.isAuthenticated, state.isLoading, trySignInSilently]);

    // if the user is not logged in Redirect to login
    if (!AuthManager.isLoggedIn() || ssoSessionExpired) {
        return (
            <Redirect to={{ pathname: '/login' }} />
        );
    }

    // Hold rendering until the SSO session has been validated/restored so that
    // child pages do not fire API calls without a valid token.
    if (!ssoSessionChecked) {
        return (
            <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
                <CircularProgress />
            </Box>
        );
    }

    return (
        <>
        <Snackbar
            open={idpUnavailable}
            anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
            autoHideDuration={10000}
            onClose={() => setIdpUnavailable(false)}
            message="Unable to verify your session with the identity provider. Please contact your administrator."
        />
        <Router>

            <div className={classes.root}>
                <CssBaseline />
                <nav className={classes.drawer}>
                    <Hidden smUp implementation="js">
                        <Navigator
                            PaperProps={{ style: { width: drawerWidth } }}
                            variant="temporary"
                            open={mobileOpen}
                            onClose={handleDrawerToggle}
                        />
                    </Hidden>
                    <Hidden xsDown implementation="css">
                        <Navigator PaperProps={{ style: { width: drawerWidth } }} />
                    </Hidden>
                </nav>
                <div className={classes.app}>
                    <Header onDrawerToggle={handleDrawerToggle} />
                    <main className={classes.main}>
                        <Content>
                            <Switch>
                                <Route exact path='/' component={Nodes} />
                                <Route exact path='/proxy-services' component={ProxyService} />
                                <Route exact path='/registry-resources' component={RegistryResources} />
                                <Route exact path='/endpoints' component={Endpoints} />
                                <Route exact path='/inbound-endpoints' component={InboundEndpoints} />
                                <Route exact path='/message-processors' component={MessageProcessors} />
                                <Route exact path='/message-stores' component={MessageStores} />
                                <Route exact path='/apis' component={APIs} />
                                <Route exact path='/templates' component={Templates} />
                                <Route exact path='/sequences' component={Sequences} />
                                <Route exact path='/tasks' component={Tasks}/>
                                <Route exact path='/local-entries' component={LocalEntries}/>
                                <Route exact path='/data-services' component={DataServices}/>
                                <Route exact path='/data-sources' component={DataSources}/>
                                <Route exact path='/connectors' component={Connectors} />
                                <Route exact path='/carbon-applications' component={CarbonApplications} />
                                <Route exact path='/log-files' component={LogFiles} />
                                <Route exact path='/log-configs' component={LogConfigs}/>
                                <Route exact path='/log-configs/add' component={AddLogConfig}/>
                                <Route exact path='/users' component={Users}/>
                                <Route exact path='/users/add' component={AddUsers}/>
                                <Route exact path='/roles/add' component={AddRoles}/>
                                <Route exact path='/roles' component={Roles}/>
                                <Route exact path='/update-password' component={UpdatePassword}/>
                                <Route exact path='/services' component={Services}/>
                                <Route exact path='/listeners' component={Listeners}/>
                                <Route exact path='/siddhi-applications' component={SiddhiApplications}/>
                                <Route exact path='/sources' component={Sources}/>
                                <Route exact path='/sinks' component={Sinks}/>
                                <Route exact path='/queries' component={Queries}/>
                                <Route exact path='/stores' component={Stores}/>
                                <Route exact path='/windows' component={Windows}/>
                                <Route exact path='/aggregations' component={Aggregations}/>
                            </Switch>
                        </Content>
                    </main>
                    <footer className={classes.footer}>
                        <Typography variant="body2" color="textSecondary" align="center">
                            {`© 2005 - ${new Date().getFullYear()} WSO2 LLC. All Rights Reserved.`}
                        </Typography>
                    </footer>
                </div>
            </div>
        </Router>
        </>
    );
}

Layout.propTypes = {
    classes: PropTypes.object.isRequired,
};

export default withStyles(styles)(Layout);
