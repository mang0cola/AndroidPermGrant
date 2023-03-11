function get_target_uid_ps(uid){
    // get the uidPermissionState of taret uid
    var target_uid_state

    Java.perform(function(){
        var SparseArray = Java.use('android.util.SparseArray')
        var UserPermissionState = Java.use('com.android.server.pm.permission.UserPermissionState')
        var UidPermissionState = Java.use('com.android.server.pm.permission.UidPermissionState')

        Java.choose('com.android.server.pm.permission.DevicePermissionState',{

            onMatch: function(instance){
                var user_states_array = instance.mUserStates.value
                user_states_array = Java.cast(user_states_array, SparseArray)

                var user_state_0 = user_states_array.get(0)
                user_state_0 = Java.cast(user_state_0, UserPermissionState)

                var uid_states_array = user_state_0.mUidStates.value

                target_uid_state = uid_states_array.get(uid)
                if(target_uid_state != null){
                    target_uid_state = Java.cast(target_uid_state, UidPermissionState)
                }
            },
            onComplete: function (){

            }

        })
    })
    return target_uid_state
}


function get_permission(perm_name){
    // get Permission instance from PermissionRegistry
    var perm
    Java.perform(function(){
        Java.choose('com.android.server.pm.permission.PermissionRegistry',{

            onMatch: function(instance){
                perm = instance.getPermission(perm_name)
            },
            onComplete: function (){
                
            }

        })
    })
    return perm
}


function list_perm_of_uid(uid){
    // print all permissions granted to uid
    var uid_perm_state = get_target_uid_ps(uid)
    var uid_perms = uid_perm_state.mPermissions.value

    if(uid_perms == null){
        send('no permission granted to ' + uid)
        return
    }

    var keyset = uid_perms.keySet()
    var it = keyset.iterator()
    while(it.hasNext()){
        var key = it.next().toString()
        send('permission: ' + key)
    }

    return uid_perms
}


function grant_perm_to_uid(perm_name, uid){

    var uid_perm_state = get_target_uid_ps(uid)
    
    if(uid_perm_state == null){
        send(perm_name + ' grant to ' + uid + ' failed.\n' + uid +' may not exists in system.')
        return
    }

    var perm = get_permission(perm_name)
    var grant_result = uid_perm_state.grantPermission(perm)
    if(grant_result){
        send(perm_name + ' grant to ' + uid + ' done.')
    } else {
        send(perm_name + ' already granted to ' + uid + ' before.')
    }
    
}

function revoke_perm_from_uid(perm_name, uid){

    var uid_perm_state = get_target_uid_ps(uid)
    
    if(uid_perm_state == null){
        send(perm_name + ' revoke from ' + uid + ' failed.\n' + uid +' may not exists in system.')
        return
    }

    var perm = get_permission(perm_name)
    var revoke_result = uid_perm_state.revokePermission(perm)

    if(revoke_result){
        send(perm_name + ' revoke from ' + uid + ' done.')
    } else {
        send(perm_name + ' already revoked from ' + uid + ' before.')
    }

}

rpc.exports = {
    grantPermToUid : grant_perm_to_uid,
    revokePermFromUid : revoke_perm_from_uid,
    getPermission : get_permission,
    listPermOfUid : list_perm_of_uid
}



// Java.perform(function(){

//     get_permission('android.permission.ACCESS_BACKGROUND_LOCATION')

//     grant_perm_to_uid('android.permission.ACCESS_BACKGROUND_LOCATION', 10263)

//     list_perm_of_uid(10263)

//     revoke_perm_from_uid('android.permission.ACCESS_BACKGROUND_LOCATION', 10263)

// })